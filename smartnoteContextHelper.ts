import {TelephonyStatus} from '../../../../common/components/TelephoneStatusIcon/TelephonyStatus';
import {TelephonyDetails} from '../../../../common/telephony/TelephonyInterface';
import {CustomerTabsState, TabState} from '../../../../redux/customerTabs/customerTabs';
import {MemberInformationState} from '../../redux/memberInformation/MemberInformationState';
import {WrapUpFormState} from '../WrapUp/Wrapup.types';

import {SmartNotesGlobalState} from './SmartNotesInterfaces';

type ActiveCallOwnerStateLike = {
  callKey?: string;
  memberId?: string;
  tabIndex?: number;
  endCallStreamTriggered?: boolean;
};

type ResolveOwnerCandidateParams = {
  activeTabIndex: number;
  firstMemberOrPatientTabIndex: number;
  firstMemberOrPatientTabMemberId: string;
  tabsState: CustomerTabsState;
  telephonyMemberId: string;
  telephonyPatientId: string;
  tabMemberId: string;
  tabPatientId: string;
};

type ComputeEndCallFlowParams = {
  useOwnerTabContext: boolean;
  telephonyStatus: TelephonyStatus;
  previousStatus: TelephonyStatus | null;
  callOwnerKey: string;
  activeCallOwnerState: ActiveCallOwnerStateLike | null;
  canTriggerEndCallFromOwnerContext: boolean;
  pciFlag: boolean;
  acUs9494658: boolean;
  isPbm: boolean;
  isPharmacy: boolean;
  autoCallRecordEnabled: boolean;
  pharmacySmartNotesEnabled: boolean;
  stopAutomaticNotes: boolean;
  previousSmartNotes: string;
  callOwnerMemberIdRefCurrent: string | null;
  isAgentAfterCallWorkInWwe: boolean;
  isTelephonyStatusAfterCallWorkForAmazon: boolean;
  acDe1362105b: boolean;
  eventCallCheck: boolean;
  // callUuid || ucid only — no member-UCID fallbacks; empty when telephony clears at disconnect
  rawTelephonyCallKey: string;
};

type ComputeEndCallFlowResult = {
  isActiveCallStatusNow: boolean;
  isEnteringConnectedWithCall: boolean;
  shouldInitializeOwnerForActiveCall: boolean;
  isEndCallStatus: boolean;
  shouldTriggerDisconnectedFallback: boolean;
  shouldTriggerOwnerDisconnectedLateMount: boolean;
  shouldTriggerEndCallForOwnerContext: boolean;
  hasTriggeredEndCallStreamForCall: boolean;
  isCallKeyMatchingOwnerState: boolean;
  shouldTriggerOwnerEndCallStream: boolean;
};

type BuildContextParams = {
  telephonyDetails: TelephonyDetails;
  tabsState: CustomerTabsState;
  memberInformation: MemberInformationState;
  wrapUpFormValues: Partial<WrapUpFormState> | undefined;
  useOwnerTabContext: boolean;
  activeCallOwnerState: ActiveCallOwnerStateLike | null;
  callOwnerMemberIdRefCurrent: string | null;
  UCID?: string;
  memberId?: string;
};

type BuildContextResult = {
  activeTabIndex: number;
  firstMemberOrPatientTabIndex: number;
  firstMemberOrPatientTabMemberId: string;
  ownerTabIndex: number;
  effectiveTabIndex: number;
  effectiveMemberId: string;
  effectivePatientId: string;
  previousSmartNotes: string;
  ucid: string;
  callUuid: string;
  telephonyMemberId: string;
  telephonyPatientId: string;
  callOwnerKey: string;
  currentTabMemberId: string;
  currentTabPatientId: string;
  tabMemberId: string;
  tabPatientId: string;
  reportingMemberId: string;
  isIvrOwnerTab: boolean;
  canTriggerEndCallFromCurrentTab: boolean;
  canTriggerEndCallFromOwnerContext: boolean;
  streamUcid: string;
};

type ResolveEffectiveSmartNotesGlobalStateParams = {
  useOwnerTabContext: boolean;
  effectiveTabIndex: number;
  activeTabIndex: number;
  tabsState: CustomerTabsState;
  smartNotesGlobalState: SmartNotesGlobalState;
};

type ResolveEffectiveSmartNotesGlobalStateResult = {
  shouldRouteOwnerContextState: boolean;
  effectiveSmartNotesGlobalState: SmartNotesGlobalState;
  stopAutomaticNotes: boolean;
  hasSmartNotesErrorForCurrentTab: boolean;
};

export class SmartNotesContextHelper {
  static shouldRouteOwnerContextState(
    useOwnerTabContext: boolean,
    effectiveTabIndex: number,
    activeTabIndex: number
  ): boolean {
    return useOwnerTabContext && effectiveTabIndex !== activeTabIndex;
  }

  static shouldRunOwnerContextOnlyFlow(useOwnerTabContext: boolean): boolean {
    return useOwnerTabContext;
  }

  static resolveEffectiveSmartNotesGlobalState(
    params: ResolveEffectiveSmartNotesGlobalStateParams
  ): ResolveEffectiveSmartNotesGlobalStateResult {
    const {useOwnerTabContext, effectiveTabIndex, activeTabIndex, tabsState, smartNotesGlobalState} = params;
    const shouldRouteOwnerContextState = SmartNotesContextHelper.shouldRouteOwnerContextState(
      useOwnerTabContext,
      effectiveTabIndex,
      activeTabIndex
    );
    const ownerContextSmartNotesGlobalState = shouldRouteOwnerContextState
      ? tabsState?.tabs?.[effectiveTabIndex]?.customerState?.smartNotesGlobalState
      : undefined;
    const effectiveSmartNotesGlobalState = ownerContextSmartNotesGlobalState || smartNotesGlobalState;

    return {
      shouldRouteOwnerContextState,
      effectiveSmartNotesGlobalState,
      stopAutomaticNotes: shouldRouteOwnerContextState
        ? Boolean(effectiveSmartNotesGlobalState?.stopAutomaticNotes)
        : Boolean(smartNotesGlobalState?.stopAutomaticNotes),
      hasSmartNotesErrorForCurrentTab: shouldRouteOwnerContextState
        ? Boolean(effectiveSmartNotesGlobalState?.isError)
        : Boolean(smartNotesGlobalState?.isError)
    };
  }

  static getNonOwnerSmartNotesVisibilityWhenEnabled(hasSmartNotesDataOrErrorForCurrentTab: boolean): boolean {
    return hasSmartNotesDataOrErrorForCurrentTab;
  }

  static normalize(value?: string): string {
    return (value || '').trim().toLowerCase();
  }

  static resolveOwnerCandidate(params: ResolveOwnerCandidateParams): {
    candidateOwnerMemberId: string;
    candidateOwnerTabIndex: number;
  } {
    const {
      activeTabIndex,
      firstMemberOrPatientTabIndex,
      firstMemberOrPatientTabMemberId,
      tabsState,
      telephonyMemberId,
      telephonyPatientId,
      tabMemberId,
      tabPatientId
    } = params;

    let candidateOwnerMemberId = '';
    let candidateOwnerTabIndex = activeTabIndex;

    if (SmartNotesContextHelper.normalize(telephonyMemberId) !== '') {
      candidateOwnerMemberId = telephonyMemberId;
    } else if (SmartNotesContextHelper.normalize(telephonyPatientId) !== '') {
      candidateOwnerMemberId = telephonyPatientId;
    } else if (SmartNotesContextHelper.normalize(firstMemberOrPatientTabMemberId) !== '') {
      // No telephony identity: lock owner to the first opened member/patient tab for this call.
      candidateOwnerMemberId = firstMemberOrPatientTabMemberId;
      if (firstMemberOrPatientTabIndex > 0) {
        candidateOwnerTabIndex = firstMemberOrPatientTabIndex;
      }
    } else if (SmartNotesContextHelper.normalize(tabMemberId) !== '') {
      // Fallback: use current tab member ID when telephony identifiers are unavailable.
      candidateOwnerMemberId = tabMemberId;
    } else if (SmartNotesContextHelper.normalize(tabPatientId) !== '') {
      candidateOwnerMemberId = tabPatientId;
    }

    const resolvedOwnerTabIndex = SmartNotesContextHelper.findMatchingMemberOrPatientTabIndex(
      tabsState,
      candidateOwnerMemberId
    );

    if (resolvedOwnerTabIndex > 0) {
      candidateOwnerTabIndex = resolvedOwnerTabIndex;
    }

    if (
      candidateOwnerMemberId &&
      firstMemberOrPatientTabIndex > 0 &&
      SmartNotesContextHelper.normalize(firstMemberOrPatientTabMemberId) ===
        SmartNotesContextHelper.normalize(candidateOwnerMemberId)
    ) {
      candidateOwnerTabIndex = firstMemberOrPatientTabIndex;
    }

    return {candidateOwnerMemberId, candidateOwnerTabIndex};
  }

  static isOwnerContextResolvedToCurrentOwner(params: {
    useOwnerTabContext: boolean;
    candidateOwnerTabIndex: number;
    effectiveTabIndex: number;
    candidateOwnerMemberId: string;
    stableOwnerReportingMemberId: string;
  }): boolean {
    const {
      useOwnerTabContext,
      candidateOwnerTabIndex,
      effectiveTabIndex,
      candidateOwnerMemberId,
      stableOwnerReportingMemberId
    } = params;

    if (!useOwnerTabContext) {
      return true;
    }

    return (
      candidateOwnerTabIndex === effectiveTabIndex &&
      SmartNotesContextHelper.normalize(candidateOwnerMemberId) ===
        SmartNotesContextHelper.normalize(stableOwnerReportingMemberId)
    );
  }

  static findMatchingMemberOrPatientTabIndex(tabsState: CustomerTabsState, ownerIdentifier: string): number {
    const normalizedOwnerIdentifier = SmartNotesContextHelper.normalize(ownerIdentifier);

    if (!normalizedOwnerIdentifier) {
      return -1;
    }

    return (
      tabsState?.tabs?.findIndex((tab: TabState, index: number) => {
        if (index === 0) return false;

        const identifiers = tab?.customerState?.memberInformationState?.memberIdentifiers;
        return (
          SmartNotesContextHelper.normalize(identifiers?.memberId) === normalizedOwnerIdentifier ||
          SmartNotesContextHelper.normalize(identifiers?.patientId) === normalizedOwnerIdentifier
        );
      }) ?? -1
    );
  }

  static computeEndCallFlow(params: ComputeEndCallFlowParams): ComputeEndCallFlowResult {
    const {
      useOwnerTabContext,
      telephonyStatus,
      previousStatus,
      callOwnerKey,
      activeCallOwnerState,
      canTriggerEndCallFromOwnerContext,
      pciFlag,
      acUs9494658,
      isPbm,
      isPharmacy,
      autoCallRecordEnabled,
      pharmacySmartNotesEnabled,
      stopAutomaticNotes,
      previousSmartNotes,
      callOwnerMemberIdRefCurrent,
      isAgentAfterCallWorkInWwe,
      isTelephonyStatusAfterCallWorkForAmazon,
      acDe1362105b,
      eventCallCheck,
      rawTelephonyCallKey
    } = params;

    const isActiveCallStatusNow =
      telephonyStatus === TelephonyStatus.ConnectedWithCall || telephonyStatus === TelephonyStatus.ConnectedAws;
    const isEnteringConnectedWithCall =
      telephonyStatus === TelephonyStatus.ConnectedWithCall && previousStatus !== TelephonyStatus.ConnectedWithCall;
    const shouldInitializeOwnerForActiveCall =
      useOwnerTabContext &&
      isActiveCallStatusNow &&
      (!activeCallOwnerState || activeCallOwnerState.callKey !== callOwnerKey || !activeCallOwnerState.memberId);

    const isEndCallStatus =
      telephonyStatus === TelephonyStatus.Connected ||
      telephonyStatus === TelephonyStatus.ConnectedAws ||
      telephonyStatus === TelephonyStatus.Disconnected ||
      (!acDe1362105b && (isAgentAfterCallWorkInWwe || isTelephonyStatusAfterCallWorkForAmazon));

    const disconnectedAfterConnectedWithCall =
      telephonyStatus === TelephonyStatus.Disconnected && previousStatus === TelephonyStatus.ConnectedWithCall;
    const shouldTriggerDisconnectedFallback =
      useOwnerTabContext &&
      disconnectedAfterConnectedWithCall &&
      canTriggerEndCallFromOwnerContext &&
      (!pciFlag || acUs9494658) &&
      ((isPbm && autoCallRecordEnabled) || (isPharmacy && pharmacySmartNotesEnabled)) &&
      (!stopAutomaticNotes || !previousSmartNotes);

    const shouldTriggerOwnerDisconnectedLateMount =
      useOwnerTabContext &&
      telephonyStatus === TelephonyStatus.Disconnected &&
      previousStatus === null &&
      canTriggerEndCallFromOwnerContext &&
      Boolean(activeCallOwnerState?.memberId || callOwnerMemberIdRefCurrent) &&
      !activeCallOwnerState?.endCallStreamTriggered &&
      (!stopAutomaticNotes || !previousSmartNotes);

    const shouldTriggerEndCallForOwnerContext =
      useOwnerTabContext &&
      telephonyStatus === TelephonyStatus.Disconnected &&
      previousStatus !== TelephonyStatus.Disconnected &&
      canTriggerEndCallFromOwnerContext &&
      Boolean(activeCallOwnerState?.memberId) &&
      !activeCallOwnerState?.endCallStreamTriggered &&
      (!stopAutomaticNotes || !previousSmartNotes);

    const hasTriggeredEndCallStreamForCall =
      Boolean(activeCallOwnerState) &&
      activeCallOwnerState?.callKey === callOwnerKey &&
      Boolean(activeCallOwnerState?.endCallStreamTriggered);

    // Block stream when telephony shows a different non-empty call key than the stored owner state.
    // Handles rapid IVR auto-pop and the WWE-to-new-call scenario where owner state is stale.
    const isCallKeyMatchingOwnerState =
      !activeCallOwnerState || activeCallOwnerState.callKey === callOwnerKey || !rawTelephonyCallKey;

    const shouldTriggerOwnerEndCallStream =
      isCallKeyMatchingOwnerState &&
      ((useOwnerTabContext && eventCallCheck && isEndCallStatus) ||
        shouldTriggerDisconnectedFallback ||
        shouldTriggerOwnerDisconnectedLateMount ||
        shouldTriggerEndCallForOwnerContext) &&
      !hasTriggeredEndCallStreamForCall;

    return {
      isActiveCallStatusNow,
      isEnteringConnectedWithCall,
      shouldInitializeOwnerForActiveCall,
      isEndCallStatus,
      shouldTriggerDisconnectedFallback,
      shouldTriggerOwnerDisconnectedLateMount,
      shouldTriggerEndCallForOwnerContext,
      hasTriggeredEndCallStreamForCall,
      isCallKeyMatchingOwnerState,
      shouldTriggerOwnerEndCallStream
    };
  }

  static buildContext(params: BuildContextParams): BuildContextResult {
    const {
      telephonyDetails,
      tabsState,
      memberInformation,
      wrapUpFormValues,
      useOwnerTabContext,
      activeCallOwnerState,
      callOwnerMemberIdRefCurrent,
      UCID,
      memberId
    } = params;

    const activeTabIndex = tabsState?.activeTabIndex || 0;

    const {firstMemberOrPatientTabIndex, firstMemberOrPatientTabMemberId} =
      SmartNotesContextHelper.resolveFirstMemberTab(tabsState);

    // Dynamically resolve owner tab from current tabsState so a tab that loaded after the initial
    // ownership lock (IVR auto-pop race condition) is correctly targeted at stream-fire time.
    const ownerTabIndexFromSearch = activeCallOwnerState?.memberId
      ? SmartNotesContextHelper.findMatchingMemberOrPatientTabIndex(tabsState, activeCallOwnerState.memberId)
      : -1;

    const ownerTabIndex =
      ownerTabIndexFromSearch > 0
        ? ownerTabIndexFromSearch
        : (activeCallOwnerState?.tabIndex ??
          (firstMemberOrPatientTabIndex > 0 ? firstMemberOrPatientTabIndex : activeTabIndex));
    const ownerTabState = ownerTabIndex >= 0 ? tabsState?.tabs?.[ownerTabIndex] : undefined;
    const ownerTabMemberInformation = ownerTabState?.customerState?.memberInformationState;
    const ownerTabWrapUpFormValues = ownerTabState?.customerState?.wrapUpFormState;

    const effectiveMemberInformation =
      useOwnerTabContext && ownerTabMemberInformation ? ownerTabMemberInformation : memberInformation;
    const effectiveWrapUpFormValues =
      useOwnerTabContext && ownerTabWrapUpFormValues ? ownerTabWrapUpFormValues : wrapUpFormValues;

    const effectiveTabIndex = useOwnerTabContext && ownerTabIndex > 0 ? ownerTabIndex : activeTabIndex;
    const effectiveMemberId =
      effectiveMemberInformation?.memberIdentifiers?.memberId || effectiveMemberInformation?.memberId || '';
    const effectivePatientId = effectiveMemberInformation?.memberIdentifiers?.patientId || '';
    const previousSmartNotes = effectiveWrapUpFormValues?.smartNotes?.data || '';

    const ucid = telephonyDetails?.UCID || '';
    const callUuid = telephonyDetails?.callUuid || '';
    const telephonyMemberId = telephonyDetails?.ENT_RXCMEMID || '';
    const telephonyPatientId = telephonyDetails?.ENT_IRISPATID || '';

    const callOwnerKey = callUuid || ucid || ownerTabMemberInformation?.ucid || UCID || '__unknown__';

    const currentTabMemberId = memberInformation?.memberIdentifiers?.memberId || memberInformation?.memberId || '';
    const currentTabPatientId = memberInformation?.memberIdentifiers?.patientId || '';
    const tabMemberId = effectiveMemberId;
    const tabPatientId = effectivePatientId;
    const reportingMemberId = tabMemberId || activeCallOwnerState?.memberId || currentTabMemberId || memberId || '';

    const idMatches = SmartNotesContextHelper.resolveIdMatches({
      telephonyMemberId,
      telephonyPatientId,
      tabMemberId,
      tabPatientId,
      ucid,
      UCID,
      firstMemberOrPatientTabMemberId
    });

    const isIvrOwnerTab = SmartNotesContextHelper.resolveIsIvrOwnerTab({
      idMatches,
      tabMemberId,
      callOwnerMemberIdRefCurrent,
      activeCallOwnerState
    });

    const memberOrPatientTabsCount =
      tabsState?.tabs?.slice(1)?.filter((tab: TabState) => {
        const identifiers = tab?.customerState?.memberInformationState?.memberIdentifiers;
        return Boolean(identifiers?.memberId || identifiers?.patientId);
      })?.length || 0;

    const isMultiMemberOrPatientTabs = memberOrPatientTabsCount > 1;
    const canTriggerEndCallFromCurrentTab = !isMultiMemberOrPatientTabs || isIvrOwnerTab;
    const canTriggerEndCallFromOwnerContext =
      !useOwnerTabContext ||
      canTriggerEndCallFromCurrentTab ||
      Boolean(
        activeCallOwnerState?.memberId ||
        callOwnerMemberIdRefCurrent ||
        firstMemberOrPatientTabMemberId ||
        tabMemberId ||
        tabPatientId
      );

    return {
      activeTabIndex,
      firstMemberOrPatientTabIndex,
      firstMemberOrPatientTabMemberId,
      ownerTabIndex,
      effectiveTabIndex,
      effectiveMemberId,
      effectivePatientId,
      previousSmartNotes,
      ucid,
      callUuid,
      telephonyMemberId,
      telephonyPatientId,
      callOwnerKey,
      currentTabMemberId,
      currentTabPatientId,
      tabMemberId,
      tabPatientId,
      reportingMemberId,
      isIvrOwnerTab,
      canTriggerEndCallFromCurrentTab,
      canTriggerEndCallFromOwnerContext,
      streamUcid: ucid || UCID || ''
    };
  }

  private static resolveFirstMemberTab(tabsState: CustomerTabsState): {
    firstMemberOrPatientTabIndex: number;
    firstMemberOrPatientTabMemberId: string;
  } {
    const firstMemberOrPatientTabIndex =
      tabsState?.tabs?.findIndex((tab: TabState, index: number) => {
        if (index === 0) return false;
        const identifiers = tab?.customerState?.memberInformationState?.memberIdentifiers;
        return Boolean(identifiers?.memberId || identifiers?.patientId);
      }) ?? -1;

    const firstMemberOrPatientTab =
      firstMemberOrPatientTabIndex >= 0 ? tabsState?.tabs?.[firstMemberOrPatientTabIndex] : null;

    const firstMemberOrPatientTabMemberId =
      firstMemberOrPatientTab?.customerState?.memberInformationState?.memberIdentifiers?.memberId ||
      firstMemberOrPatientTab?.customerState?.memberInformationState?.memberIdentifiers?.patientId ||
      '';

    return {firstMemberOrPatientTabIndex, firstMemberOrPatientTabMemberId};
  }

  private static resolveIdMatches(params: {
    telephonyMemberId: string;
    telephonyPatientId: string;
    tabMemberId: string;
    tabPatientId: string;
    ucid: string;
    UCID?: string;
    firstMemberOrPatientTabMemberId: string;
  }) {
    const n = SmartNotesContextHelper.normalize;
    const {
      telephonyMemberId,
      telephonyPatientId,
      tabMemberId,
      tabPatientId,
      ucid,
      UCID,
      firstMemberOrPatientTabMemberId
    } = params;

    const hasMemberIdMatch =
      n(telephonyMemberId) !== '' && n(tabMemberId) !== '' && n(telephonyMemberId) === n(tabMemberId);
    const hasPatientIdMatch =
      n(telephonyPatientId) !== '' && n(tabPatientId) !== '' && n(telephonyPatientId) === n(tabPatientId);
    const hasTelephonyIdentity = n(telephonyMemberId) !== '' || n(telephonyPatientId) !== '';
    const hasTabIdentity = n(tabMemberId) !== '' || n(tabPatientId) !== '';
    const hasUcidMatch = n(ucid) !== '' && n(UCID) !== '' && n(ucid) === n(UCID);
    const isFirstOpenedMemberOrPatientTab =
      n(firstMemberOrPatientTabMemberId) !== '' && n(tabMemberId) === n(firstMemberOrPatientTabMemberId);

    return {
      hasMemberIdMatch,
      hasPatientIdMatch,
      hasTelephonyIdentity,
      hasTabIdentity,
      hasUcidMatch,
      isFirstOpenedMemberOrPatientTab
    };
  }

  private static resolveIsIvrOwnerTab(params: {
    idMatches: ReturnType<typeof SmartNotesContextHelper.resolveIdMatches>;
    tabMemberId: string;
    callOwnerMemberIdRefCurrent: string | null;
    activeCallOwnerState: ActiveCallOwnerStateLike | null;
  }): boolean {
    const {idMatches, tabMemberId, callOwnerMemberIdRefCurrent, activeCallOwnerState} = params;
    const {
      hasMemberIdMatch,
      hasPatientIdMatch,
      hasTelephonyIdentity,
      hasTabIdentity,
      hasUcidMatch,
      isFirstOpenedMemberOrPatientTab
    } = idMatches;
    const n = SmartNotesContextHelper.normalize;

    if (hasTelephonyIdentity) {
      return hasMemberIdMatch || hasPatientIdMatch || (!hasTabIdentity && hasUcidMatch);
    }
    if (callOwnerMemberIdRefCurrent !== null) {
      return n(tabMemberId) === n(callOwnerMemberIdRefCurrent || '');
    }
    if (activeCallOwnerState?.memberId) {
      return n(tabMemberId) === n(activeCallOwnerState.memberId);
    }
    if (isFirstOpenedMemberOrPatientTab) {
      return true;
    }
    return hasUcidMatch;
  }
}

