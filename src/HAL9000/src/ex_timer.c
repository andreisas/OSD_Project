#include "HAL9000.h"
#include "ex_timer.h"
#include "iomu.h"
#include "thread_internal.h"


STATUS
ExTimerInit(
    OUT     PEX_TIMER       Timer,
    IN      EX_TIMER_TYPE   Type,
    IN      QWORD           Time
    )
{
    STATUS status;

    if (NULL == Timer)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (Type > ExTimerTypeMax)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    status = STATUS_SUCCESS;

    memzero(Timer, sizeof(EX_TIMER));


    ExEventInit(&Timer->TimerEvent, ExEventTypeNotification, FALSE);
    INTR_STATE state;
    LockAcquire(&m_globalTimerList.TimerListLock, &state);
    InsertOrderedList(&m_globalTimerList.TimerListHead, &Timer->TimerListElem, ExTimerCompareListElems, NULL);
    LockRelease(&m_globalTimerList.TimerListLock, state);


    Timer->Type = Type;
    if (Timer->Type != ExTimerTypeAbsolute)
    {
        // relative time

        // if the time trigger time has already passed the timer will
        // be signaled after the first scheduler tick
        Timer->TriggerTimeUs = IomuGetSystemTimeUs() + Time;
        Timer->ReloadTimeUs = Time;
    }
    else
    {
        // absolute
        Timer->TriggerTimeUs = Time;
    }

    return status;
}

void
ExTimerStart(
    IN      PEX_TIMER       Timer
    )
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    Timer->TimerStarted = TRUE;
}

void
ExTimerStop(
    IN      PEX_TIMER       Timer
    )
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    Timer->TimerStarted = FALSE;
    ExEventSignal(&Timer->TimerEvent);
}

void
ExTimerWait(
    INOUT   PEX_TIMER       Timer
    )
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    if (IomuGetSystemTimeUs() < Timer->TriggerTimeUs && Timer->TimerStarted)
    {
        ExEventWaitForSignal(&Timer->TimerEvent);
    }
}

void
ExTimerUninit(
    INOUT   PEX_TIMER       Timer
    )
{
    ASSERT(Timer != NULL);

    ExTimerStop(Timer);

    Timer->TimerUninited = TRUE;
    INTR_STATE state;
    LockAcquire(&m_globalTimerList.TimerListLock,&state);
    RemoveEntryList(&Timer->TimerListElem);
    LockRelease(&m_globalTimerList.TimerListLock,state );
}

INT64
ExTimerCompareTimers(
    IN      PEX_TIMER     FirstElem,
    IN      PEX_TIMER     SecondElem
)
{
    return FirstElem->TriggerTimeUs - SecondElem->TriggerTimeUs;
}

void ExTimerSystemPreinit(void)
{
    InitializeListHead(&m_globalTimerList.TimerListHead);
    LockInit(&m_globalTimerList.TimerListLock);
}
static STATUS(_cdecl ExTimerCheck) (IN PLIST_ENTRY ListEntry, IN_OPT PVOID Context)
{
    ASSERT(ListEntry != NULL);
    UNREFERENCED_PARAMETER(Context);
    PEX_TIMER timer = CONTAINING_RECORD(ListEntry, EX_TIMER, TimerListElem);
    if (IomuGetSystemTimeUs() >= timer->TriggerTimeUs)
        ExEventSignal(&timer->TimerEvent);
    return STATUS_SUCCESS;
}

void ExTimerCheckAll(void) {

    INTR_STATE state;
    LockAcquire(&m_globalTimerList.TimerListLock, &state);
    ForEachElementExecute(&m_globalTimerList.TimerListHead, ExTimerCheck, NULL, FALSE);
    LockRelease(&m_globalTimerList.TimerListLock, state);

}

INT64 ExTimerCompareListElems(PLIST_ENTRY t1, PLIST_ENTRY t2, PVOID context) {
    ASSERT(t1 != NULL);
    ASSERT(t2 != NULL);
    UNREFERENCED_PARAMETER(context);
    return ExTimerCompareTimers(CONTAINING_RECORD(t1, EX_TIMER, TimerListElem), CONTAINING_RECORD(t2, EX_TIMER, TimerListElem));
}
