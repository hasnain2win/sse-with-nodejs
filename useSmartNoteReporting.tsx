
import {useRef} from 'react';

import {
  useCreateSmartNoteReportingAttemptMutation,
  useUpdateSmartNoteReportingAttemptMutation
} from '../../../../redux/api/member/smartNoteReporting';
import {
  UpdateSmartNoteReportingRequest,
  GenerationPhase,
  LifecycleStatus,
  LIFECYCLE_STATUS,
  FINAL_STATUS
} from '../../../../redux/api/member/smartNoteReporting/types';
import {useMemberInformationState} from '../../../../common/hooks/useMemberInformationState';

type PendingUpdate = Omit<UpdateSmartNoteReportingRequest, 'uid'>;

type ReportingState = {
  reportingUidRef: number | null;
  generationStartTimeRef: number | null;
  editStartTimeRef: number | null;
  totalEditTimeMsRef: number;
  hasCreatedAttemptRef: boolean;
  lifecycleStatusesReported: Set<string>;
  pendingUpdates: PendingUpdate[];
  updateChain: Promise<void>;
  vapDualAccess?: boolean;
};

const createDefaultReportingState = (): ReportingState => ({
  reportingUidRef: null,
  generationStartTimeRef: null,
  editStartTimeRef: null,
  totalEditTimeMsRef: 0,
  hasCreatedAttemptRef: false,
  lifecycleStatusesReported: new Set(),
  pendingUpdates: [],
  updateChain: Promise.resolve(),
  vapDualAccess: undefined
});

const reportingStateMap = new Map<string, ReportingState>();

const getOrCreateReportingState = (ucid: string) => {
  if (!reportingStateMap.has(ucid)) {
    reportingStateMap.set(ucid, createDefaultReportingState());
  }
  return reportingStateMap.get(ucid) as ReportingState;
};

export function useSmartNoteReporting() {
  const [createSmartNoteReportingAttempt] = useCreateSmartNoteReportingAttemptMutation();
  const [updateSmartNoteReportingAttempt] = useUpdateSmartNoteReportingAttemptMutation();
  const {memberInformation} = useMemberInformationState();

  const reportingKeyRef = useRef<string | undefined>(undefined);
  const manualKeySet = useRef<boolean>(false);

  // Auto-sync key from member info unless setReportingKey was called explicitly
  const ucid = memberInformation?.ucid;
  const memberId = memberInformation?.memberIdentifiers?.memberId;
  const derivedKey = ucid && memberId ? `${ucid}-${memberId}` : undefined;
  if (derivedKey && !manualKeySet.current) {
    reportingKeyRef.current = derivedKey;
  }

  /**
   * Explicitly set the reporting key. Use this when you need to control
   * exactly when the key is captured (e.g., at ConnectedWithCall time).
   * Prevents auto-sync from overwriting the key.
   */
  const setReportingKey = (key: string | undefined) => {
    reportingKeyRef.current = key;
    manualKeySet.current = Boolean(key);
  };

  const getState = () => {
    const key = reportingKeyRef.current;
    return key ? getOrCreateReportingState(key) : null;
  };

  const queueOrSendUpdate = (update: PendingUpdate) => {
    const state = getState();
    if (!state) return;

    if (state.reportingUidRef) {
      const uid = state.reportingUidRef;
      state.updateChain = state.updateChain
        .then(() =>
          updateSmartNoteReportingAttempt({
            ...update,
            uid,
            ...(state.vapDualAccess !== undefined ? {vapDualAccess: state.vapDualAccess} : {})
          }).unwrap()
        )
        .then(() => {})
        .catch(() => {});
    } else {
      state.pendingUpdates.push(update);
    }
  };

  const createAttempt = async (
    generationPhase: GenerationPhase,
    generationRequestId: string,
    lifecycleStatus: LifecycleStatus = LIFECYCLE_STATUS.CONNECTED,
    attemptStartTime?: string,
    ucid?: string,
    vapDualAccess?: boolean,
    profileType?: string
  ) => {
    const key = reportingKeyRef.current;
    const state = getState();
    if (!key || !state) {
      return;
    }

    if (state.hasCreatedAttemptRef) {
      return;
    }
    state.hasCreatedAttemptRef = true;
    state.vapDualAccess = vapDualAccess;

    try {
      const response = await createSmartNoteReportingAttempt({
        ucid: ucid || key,
        generationPhase,
        generationRequestId,
        lifecycleStatus,
        ...(attemptStartTime && {attemptStartTime}),
        ...(vapDualAccess !== undefined ? {vapDualAccess} : {}),
        ...(profileType && {profileType})
      }).unwrap();
      state.reportingUidRef = response.uid;

      if (state.pendingUpdates.length > 0) {
        const updates = [...state.pendingUpdates];
        state.pendingUpdates = [];
        updates.forEach((update) => {
          state.updateChain = state.updateChain
            .then(() =>
              updateSmartNoteReportingAttempt({
                ...update,
                uid: response.uid,
                ...(state.vapDualAccess !== undefined ? {vapDualAccess: state.vapDualAccess} : {})
              }).unwrap()
            )
            .then(() => {})
            .catch(() => {});
        });
      }
    } catch {
      state.hasCreatedAttemptRef = false;
      state.pendingUpdates = [];
    }
  };

  const reportGenerationRequested = (generationPhase: GenerationPhase, generationRequestId: string) => {
    const state = getState();
    if (!state || !reportingKeyRef.current) return;
    if (state.lifecycleStatusesReported.has(LIFECYCLE_STATUS.REQUESTED)) return;

    state.lifecycleStatusesReported.add(LIFECYCLE_STATUS.REQUESTED);

    queueOrSendUpdate({
      lifecycleStatus: LIFECYCLE_STATUS.REQUESTED,
      generationPhase,
      generationRequestId,
      attemptStartTime: Date.now().toString()
    });
  };

  /**
   * Update reporting when transcript is not ready
   */
  const reportTranscriptNotReady = () => {
    const state = getState();
    if (!state || !reportingKeyRef.current) {
      return;
    }
    if (state.lifecycleStatusesReported.has(LIFECYCLE_STATUS.TRANSCRIPT_NOT_READY)) {
      return;
    }
    state.lifecycleStatusesReported.add(LIFECYCLE_STATUS.TRANSCRIPT_NOT_READY);

    queueOrSendUpdate({
      lifecycleStatus: LIFECYCLE_STATUS.TRANSCRIPT_NOT_READY,
      failureReason: 'Transcript is too short or not available in the VAP system.',
      finalStatus: FINAL_STATUS.FAILED
    });
  };

  /**
   * Update reporting when stream fails or times out
   */
  const reportStreamFailure = (failureReason: string, errorType: LifecycleStatus = LIFECYCLE_STATUS.STREAM_FAILURE) => {
    const state = getState();
    if (!state || !reportingKeyRef.current) return;
    if (state.lifecycleStatusesReported.has(errorType)) {
      return;
    }
    state.lifecycleStatusesReported.add(errorType);

    queueOrSendUpdate({
      lifecycleStatus: errorType,
      failureReason,
      finalStatus: FINAL_STATUS.FAILED
    });
  };

  /**
   * Update reporting when mid-call API fails
   */
  const reportMidCallFailure = (errorMessage?: string) => {
    const state = getState();
    if (!state || !reportingKeyRef.current) {
      return;
    }
    if (state.lifecycleStatusesReported.has(LIFECYCLE_STATUS.MID_CALL_FAILURE)) {
      return;
    }
    state.lifecycleStatusesReported.add(LIFECYCLE_STATUS.MID_CALL_FAILURE);

    queueOrSendUpdate({
      lifecycleStatus: LIFECYCLE_STATUS.MID_CALL_FAILURE,
      failureReason: errorMessage || 'Mid-call API request failed.'
    });
  };

  /**
   * Update reporting when Smart Note is successfully generated
   */
  const reportGenerationSuccess = () => {
    const state = getState();
    if (!state || !reportingKeyRef.current) {
      return;
    }
    if (state.lifecycleStatusesReported.has(LIFECYCLE_STATUS.GENERATED)) {
      return;
    }
    state.lifecycleStatusesReported.add(LIFECYCLE_STATUS.GENERATED);

    queueOrSendUpdate({
      lifecycleStatus: LIFECYCLE_STATUS.GENERATED,
      finalStatus: FINAL_STATUS.SUCCESS,
      generationTime: Date.now().toString()
    });
  };

  /**
   * Track when agent clicks edit button to start editing
   * Call this when edit mode begins
   */
  const reportEditStarted = () => {
    const state = getState();
    if (!state || !reportingKeyRef.current) return;

    // Capture the moment editing begins only once per active edit session.
    if (!state.editStartTimeRef) {
      state.editStartTimeRef = Date.now();
    }
  };

  /**
   * Track when agent exits edit mode and aggregate elapsed time.
   */
  const reportEditEnded = () => {
    const state = getState();
    if (!state || !reportingKeyRef.current || !state.editStartTimeRef) return;

    const attemptEditTimeMs = Date.now() - state.editStartTimeRef;
    state.totalEditTimeMsRef += attemptEditTimeMs;
    state.editStartTimeRef = null;
  };

  /**
   * Update reporting on wrap-up completion
   */
  const reportWrapUpComplete = () => {
    const state = getState();
    if (!state || !reportingKeyRef.current) {
      return;
    }
    if (state.lifecycleStatusesReported.has(LIFECYCLE_STATUS.WRAPUP_COMPLETED)) {
      return;
    }
    state.lifecycleStatusesReported.add(LIFECYCLE_STATUS.WRAPUP_COMPLETED);

    const isSummaryGenerated = state.lifecycleStatusesReported.has(LIFECYCLE_STATUS.GENERATED);
    let totalEditTimeMs = state.totalEditTimeMsRef;

    // If wrap-up happens while edit mode is still open, include that active interval.
    if (state.editStartTimeRef) {
      const activeAttemptEditTimeMs = Date.now() - state.editStartTimeRef;
      totalEditTimeMs += activeAttemptEditTimeMs;

      state.editStartTimeRef = null;
    }
    const hasAgentEdited = totalEditTimeMs > 0;

    queueOrSendUpdate({
      lifecycleStatus: LIFECYCLE_STATUS.WRAPUP_COMPLETED,
      finalStatus: isSummaryGenerated ? FINAL_STATUS.SUCCESS : FINAL_STATUS.FAILED,
      ...(hasAgentEdited && {
        agentEdited: true,
        editTimeMs: totalEditTimeMs
      })
    });
  };

  /**
   * Reset attempt state for a new mid-call generation for the same member.
   * Instance-bound so it always uses the current dispatch.
   */
  const resetAttemptState = () => {
    const key = reportingKeyRef.current;
    if (!key) return;
    const s = reportingStateMap.get(key);
    if (s) {
      if (s.editStartTimeRef) {
        s.totalEditTimeMsRef += Date.now() - s.editStartTimeRef;
      }
      s.reportingUidRef = null;
      s.generationStartTimeRef = null;
      s.editStartTimeRef = null;
      s.hasCreatedAttemptRef = false;
      s.lifecycleStatusesReported.clear();
      s.pendingUpdates = [];
      s.updateChain = Promise.resolve();
      s.vapDualAccess = undefined;
    }
  };

  /**
   * Clear reporting state entirely for the current UCID.
   * Call when switching members or ending a call.
   * Instance-bound so it always uses the current dispatch.
   */
  const clearReportingState = () => {
    const key = reportingKeyRef.current;
    if (!key) return;
    reportingStateMap.delete(key);
  };

  return {
    createAttempt,
    setReportingKey,
    reportGenerationRequested,
    reportTranscriptNotReady,
    reportStreamFailure,
    reportMidCallFailure,
    reportGenerationSuccess,
    reportEditStarted,
    reportEditEnded,
    reportWrapUpComplete,
    resetAttemptState,
    clearReportingState
  };
}
