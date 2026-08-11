const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const storePath = path.join(__dirname, 'verify-demo-store.json');

const POLICY_PACK = [
  {
    id: 'policy-admin-recovery',
    name: 'Admin Recovery Lock',
    workflowType: 'account_recovery',
    description: 'Admin and privileged accounts must complete phishing-resistant proof and security oversight.',
    conditions: ['Account tier is admin or privileged', 'Request includes MFA reset or new device enrollment'],
    requirements: ['Passkey or ID + liveness verification', 'Security manager approval'],
  },
  {
    id: 'policy-vendor-change',
    name: 'Vendor Payment Change Hold',
    workflowType: 'vendor_change',
    description: 'Banking changes require verified callback and finance approval before release.',
    conditions: ['Bank details changed', 'Request originates from email or AP portal'],
    requirements: ['Verified callback to known contact', 'Controller approval'],
  },
  {
    id: 'policy-payroll-change',
    name: 'Payroll Redirect Guard',
    workflowType: 'payroll_change',
    description: 'Direct-deposit changes must be verified on a clean secondary channel.',
    conditions: ['Payroll destination modified', 'After-hours or unmanaged device activity'],
    requirements: ['Known-channel verification', 'HR operations approval'],
  },
];

const TEAM_DIRECTORY = [
  { id: 'analyst-nadia', name: 'Nadia Brooks', role: 'Security Analyst' },
  { id: 'lead-owen', name: 'Owen Hale', role: 'IT Service Desk Lead' },
  { id: 'controller-rhea', name: 'Rhea Patel', role: 'Controller' },
  { id: 'manager-evan', name: 'Evan Stone', role: 'HR Operations Manager' },
];

const REQUEST_TEMPLATES = {
  account_recovery: {
    title: 'Privileged account recovery',
    workflowType: 'account_recovery',
    sourceSystem: 'Okta Help Desk',
    requestedBy: 'Maya Lewis',
    subjectName: 'Jordan Ames',
    department: 'Infrastructure',
    assignedTeam: 'Identity Security',
    targetSystem: 'Okta Admin Console',
    requestedChannel: 'Phone via service desk',
    targetLabel: 'Admin console access',
    requestedAction: 'Reset password and enroll replacement passkey',
    summary: 'Caller reported a lost phone and requested immediate recovery for an admin account.',
    riskScore: 92,
    priority: 'Critical',
    amountAtRisk: 0,
    verificationOptions: ['passkey', 'id_liveness'],
    requiredApprovalRoles: ['Security Analyst'],
    signals: [
      {
        id: 'signal-lost-device',
        label: 'Lost-device narrative on privileged account',
        severity: 'high',
        context: 'Matches known help-desk social-engineering pretext.',
        weight: 34,
      },
      {
        id: 'signal-geo-shift',
        label: 'Recent sign-in from new region',
        severity: 'medium',
        context: 'Login telemetry shifted from Austin to Bucharest within 6 hours.',
        weight: 21,
      },
      {
        id: 'signal-device-change',
        label: 'New MFA device request',
        severity: 'high',
        context: 'Would re-establish trust on an unverified device.',
        weight: 27,
      },
    ],
    policyIds: ['policy-admin-recovery'],
  },
  vendor_change: {
    title: 'Vendor bank-detail change',
    workflowType: 'vendor_change',
    sourceSystem: 'NetSuite AP Queue',
    requestedBy: 'Ava Martin',
    subjectName: 'Northwind Medical Supply',
    department: 'Accounts Payable',
    assignedTeam: 'Accounts Payable',
    targetSystem: 'NetSuite Vendor Master',
    requestedChannel: 'Email thread reply',
    targetLabel: 'Vendor payout route',
    requestedAction: 'Replace beneficiary account ending in 8841',
    summary: 'Vendor replied inside an existing invoice thread asking for a same-day bank-detail change.',
    riskScore: 88,
    priority: 'High',
    amountAtRisk: 148500,
    verificationOptions: ['verified_callback', 'signed_confirmation'],
    requiredApprovalRoles: ['Controller'],
    signals: [
      {
        id: 'signal-thread-shift',
        label: 'Bank detail changed inside active email thread',
        severity: 'high',
        context: 'Classic vendor email compromise pattern.',
        weight: 31,
      },
      {
        id: 'signal-urgent-language',
        label: 'Urgent settlement requested',
        severity: 'medium',
        context: 'Message asked for payment release before close of business.',
        weight: 17,
      },
      {
        id: 'signal-country-change',
        label: 'Beneficiary country differs from master record',
        severity: 'high',
        context: 'Existing vendor record is U.S.; requested bank is in a new country.',
        weight: 29,
      },
    ],
    policyIds: ['policy-vendor-change'],
  },
  payroll_change: {
    title: 'Payroll direct-deposit change',
    workflowType: 'payroll_change',
    sourceSystem: 'Workday Inbox',
    requestedBy: 'Chris Cole',
    subjectName: 'Tanya West',
    department: 'People Operations',
    assignedTeam: 'People Operations',
    targetSystem: 'Workday Payroll',
    requestedChannel: 'Personal email',
    targetLabel: 'Employee direct deposit',
    requestedAction: 'Update payroll destination before tomorrow payout',
    summary: 'Employee requested an urgent deposit redirect from a personal webmail account.',
    riskScore: 84,
    priority: 'High',
    amountAtRisk: 12400,
    verificationOptions: ['known_channel', 'id_liveness'],
    requiredApprovalRoles: ['HR Operations Manager'],
    signals: [
      {
        id: 'signal-personal-email',
        label: 'Request came from personal email',
        severity: 'medium',
        context: 'Bypasses corporate mailbox trust signals.',
        weight: 18,
      },
      {
        id: 'signal-after-hours',
        label: 'Submitted outside payroll support hours',
        severity: 'medium',
        context: 'Common pressure tactic before payroll release.',
        weight: 16,
      },
      {
        id: 'signal-bank-swap',
        label: 'Destination account fully replaced',
        severity: 'high',
        context: 'Would redirect funds without prior verification.',
        weight: 24,
      },
    ],
    policyIds: ['policy-payroll-change'],
  },
};

function timestampMinutesAgo(minutesAgo) {
  return new Date(Date.now() - minutesAgo * 60 * 1000).toISOString();
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function mergeRequestWithTemplate(request) {
  const template = REQUEST_TEMPLATES[request.workflowType];

  if (!template) {
    return request;
  }

  return {
    ...clone(template),
    ...request,
    signals: request.signals || clone(template.signals),
    verificationOptions: request.verificationOptions || clone(template.verificationOptions),
    requiredApprovalRoles: request.requiredApprovalRoles || clone(template.requiredApprovalRoles),
    policyIds: request.policyIds || clone(template.policyIds),
    verificationChallenges: request.verificationChallenges || [],
    approvals: request.approvals || [],
    auditTrail: request.auditTrail || [],
  };
}

function buildSeedState() {
  return {
    meta: {
      organizationName: 'Northstar Verify Labs',
      environment: 'demo',
      refreshedAt: new Date().toISOString(),
    },
    organizationProfile: {
      name: 'Northstar Verify Labs',
      industry: 'Business services',
      workforceSize: '1,200 employees',
      primaryIdp: 'Okta Workforce Identity',
      financeSystem: 'NetSuite',
      supportPlatform: 'ServiceNow',
      riskPosture: 'Elevated human-risk controls',
    },
    integrations: [
      {
        id: 'int-okta',
        name: 'Okta Workforce Identity',
        category: 'Identity',
        status: 'Connected',
        coverage: 'Account recovery and MFA reset events',
      },
      {
        id: 'int-servicenow',
        name: 'ServiceNow',
        category: 'Service desk',
        status: 'Connected',
        coverage: 'Help-desk request intake and operator actions',
      },
      {
        id: 'int-netsuite',
        name: 'NetSuite',
        category: 'Finance',
        status: 'Pilot',
        coverage: 'Vendor change holds and payout release controls',
      },
      {
        id: 'int-workday',
        name: 'Workday',
        category: 'HRIS',
        status: 'Planned',
        coverage: 'Payroll destination changes and employee verification',
      },
    ],
    settings: {
      verificationDefaults: [
        'Block privileged recovery until phishing-resistant proof is recorded',
        'Require verified callback for any vendor bank-detail change',
        'Require clean-channel verification for payroll redirects',
      ],
      approvalRouting: [
        'Security Analyst reviews privileged recovery requests',
        'Controller approves vendor payment-route changes',
        'HR Operations Manager approves payroll redirects',
      ],
      retention: 'Audit events retained for 180 days in demo mode',
      notifications: 'Email and Slack notifications simulated in the activity feed',
    },
    policyPack: POLICY_PACK,
    teamDirectory: TEAM_DIRECTORY,
    requests: [
      {
        id: 'VR-2401',
        ...clone(REQUEST_TEMPLATES.account_recovery),
        status: 'awaiting_verification',
        openedAt: timestampMinutesAgo(14),
        verificationChallenges: [],
        approvals: [],
        auditTrail: [
          {
            id: crypto.randomUUID(),
            type: 'request_opened',
            actor: 'System',
            detail: 'Request created from Okta Help Desk.',
            createdAt: timestampMinutesAgo(14),
          },
          {
            id: crypto.randomUUID(),
            type: 'policy_hit',
            actor: 'Policy Engine',
            detail: 'Admin Recovery Lock required phishing-resistant verification.',
            createdAt: timestampMinutesAgo(13),
          },
        ],
      },
      {
        id: 'VR-2402',
        ...clone(REQUEST_TEMPLATES.vendor_change),
        status: 'awaiting_approval',
        openedAt: timestampMinutesAgo(33),
        verificationChallenges: [
          {
            id: crypto.randomUUID(),
            methodType: 'verified_callback',
            status: 'passed',
            performedBy: 'Nadia Brooks',
            note: 'Verified against vendor master record contact.',
            createdAt: timestampMinutesAgo(27),
            completedAt: timestampMinutesAgo(25),
          },
        ],
        approvals: [],
        auditTrail: [
          {
            id: crypto.randomUUID(),
            type: 'request_opened',
            actor: 'System',
            detail: 'Vendor change request imported from NetSuite AP Queue.',
            createdAt: timestampMinutesAgo(33),
          },
          {
            id: crypto.randomUUID(),
            type: 'verification_passed',
            actor: 'Nadia Brooks',
            detail: 'Verified callback completed successfully.',
            createdAt: timestampMinutesAgo(25),
          },
        ],
      },
      {
        id: 'VR-2403',
        ...clone(REQUEST_TEMPLATES.payroll_change),
        status: 'denied',
        openedAt: timestampMinutesAgo(58),
        verificationChallenges: [
          {
            id: crypto.randomUUID(),
            methodType: 'known_channel',
            status: 'failed',
            performedBy: 'Owen Hale',
            note: 'Employee could not validate using existing contact number.',
            createdAt: timestampMinutesAgo(52),
            completedAt: timestampMinutesAgo(49),
          },
        ],
        approvals: [],
        auditTrail: [
          {
            id: crypto.randomUUID(),
            type: 'request_opened',
            actor: 'System',
            detail: 'Payroll change request imported from Workday.',
            createdAt: timestampMinutesAgo(58),
          },
          {
            id: crypto.randomUUID(),
            type: 'request_denied',
            actor: 'Owen Hale',
            detail: 'Known-channel verification failed. Request blocked.',
            createdAt: timestampMinutesAgo(49),
          },
        ],
      },
      {
        id: 'VR-2404',
        ...clone(REQUEST_TEMPLATES.account_recovery),
        status: 'verified',
        riskScore: 66,
        priority: 'Medium',
        subjectName: 'Lila Chen',
        requestedBy: 'Priya Moore',
        requestedAction: 'Reset standard account password',
        summary: 'User called in from a known device and completed callback verification.',
        policyIds: ['policy-admin-recovery'],
        assignedTeam: 'IT Support',
        targetSystem: 'ServiceNow Linked Account',
        requestedChannel: 'Phone via service desk',
        openedAt: timestampMinutesAgo(95),
        verificationOptions: ['verified_callback'],
        requiredApprovalRoles: [],
        verificationChallenges: [
          {
            id: crypto.randomUUID(),
            methodType: 'verified_callback',
            status: 'passed',
            performedBy: 'Nadia Brooks',
            note: 'Confirmed with registered mobile and device fingerprint.',
            createdAt: timestampMinutesAgo(91),
            completedAt: timestampMinutesAgo(89),
          },
        ],
        approvals: [],
        auditTrail: [
          {
            id: crypto.randomUUID(),
            type: 'request_opened',
            actor: 'System',
            detail: 'Reset request created from ServiceNow.',
            createdAt: timestampMinutesAgo(95),
          },
          {
            id: crypto.randomUUID(),
            type: 'verification_passed',
            actor: 'Nadia Brooks',
            detail: 'Callback verification passed and request released.',
            createdAt: timestampMinutesAgo(89),
          },
        ],
      },
    ],
  };
}

function ensureStoreFile() {
  if (!fs.existsSync(storePath)) {
    fs.writeFileSync(storePath, JSON.stringify(buildSeedState(), null, 2));
  }
}

function readStore() {
  ensureStoreFile();
  const rawState = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  const seed = buildSeedState();

  return {
    ...seed,
    ...rawState,
    organizationProfile: { ...seed.organizationProfile, ...(rawState.organizationProfile || {}) },
    settings: { ...seed.settings, ...(rawState.settings || {}) },
    integrations: rawState.integrations || seed.integrations,
    policyPack: rawState.policyPack || seed.policyPack,
    teamDirectory: rawState.teamDirectory || seed.teamDirectory,
    requests: (rawState.requests || seed.requests).map((request) => mergeRequestWithTemplate(request)),
  };
}

function writeStore(state) {
  state.meta.refreshedAt = new Date().toISOString();
  fs.writeFileSync(storePath, JSON.stringify(state, null, 2));
}

function getPolicyById(state, policyId) {
  return state.policyPack.find((policy) => policy.id === policyId);
}

function hydrateRequest(state, request) {
  const completedApprovals = request.approvals.filter((approval) => approval.decision === 'approved').length;
  const requiredApprovals = request.requiredApprovalRoles.length;

  return {
    ...request,
    policyPack: request.policyIds.map((policyId) => getPolicyById(state, policyId)).filter(Boolean),
    completedApprovals,
    requiredApprovals,
    verificationProgress: {
      passed: request.verificationChallenges.filter((challenge) => challenge.status === 'passed').length,
      failed: request.verificationChallenges.filter((challenge) => challenge.status === 'failed').length,
    },
  };
}

function sortedRequests(state) {
  return state.requests
    .slice()
    .sort((left, right) => new Date(right.openedAt).getTime() - new Date(left.openedAt).getTime())
    .map((request) => hydrateRequest(state, request));
}

function summarize(state) {
  const requests = sortedRequests(state);
  const activeRequests = requests.filter((request) => ['awaiting_verification', 'awaiting_approval'].includes(request.status));
  const blockedRequests = requests.filter((request) => request.status === 'denied');
  const verifiedRequests = requests.filter((request) => request.status === 'verified');
  const approvalQueue = requests.filter((request) => request.status === 'awaiting_approval');

  return {
    organizationName: state.meta.organizationName,
    environment: state.meta.environment,
    refreshedAt: state.meta.refreshedAt,
    metrics: [
      {
        id: 'open',
        label: 'Active requests',
        value: activeRequests.length,
        detail: 'Requests still blocked behind proof or approval.',
      },
      {
        id: 'exposure',
        label: 'Payment exposure',
        value: `$${activeRequests
          .reduce((sum, request) => sum + request.amountAtRisk, 0)
          .toLocaleString()}`,
        detail: 'Funds protected by the current queue.',
      },
      {
        id: 'blocked',
        label: 'Blocked attempts',
        value: blockedRequests.length,
        detail: 'Requests denied after failed proof or policy breach.',
      },
      {
        id: 'approved',
        label: 'Verified today',
        value: verifiedRequests.length,
        detail: 'Requests released after successful controls.',
      },
    ],
    queueHealth: {
      approvalQueue: approvalQueue.length,
      criticalRequests: activeRequests.filter((request) => request.priority === 'Critical').length,
      averageRiskScore:
        activeRequests.length === 0
          ? 0
          : Math.round(activeRequests.reduce((sum, request) => sum + request.riskScore, 0) / activeRequests.length),
    },
    workflowMix: [
      {
        key: 'account_recovery',
        label: 'Account recovery',
        count: requests.filter((request) => request.workflowType === 'account_recovery').length,
      },
      {
        key: 'vendor_change',
        label: 'Vendor changes',
        count: requests.filter((request) => request.workflowType === 'vendor_change').length,
      },
      {
        key: 'payroll_change',
        label: 'Payroll changes',
        count: requests.filter((request) => request.workflowType === 'payroll_change').length,
      },
    ],
  };
}

function feedFromState(state) {
  return state.requests
    .flatMap((request) =>
      request.auditTrail.map((event) => ({
        ...event,
        requestId: request.id,
        title: request.title,
      })),
    )
    .sort((left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime())
    .slice(0, 10);
}

function responsePayload(state, focusRequestId) {
  const requests = sortedRequests(state);
  const selectedRequest = focusRequestId
    ? requests.find((request) => request.id === focusRequestId)
    : requests[0] || null;

  return {
    summary: summarize(state),
    requests,
    selectedRequest,
    organizationProfile: state.organizationProfile,
    integrations: state.integrations,
    settings: state.settings,
    policyPack: state.policyPack,
    teamDirectory: state.teamDirectory,
    activityFeed: feedFromState(state),
    templates: Object.keys(REQUEST_TEMPLATES).map((key) => ({
      key,
      workflowType: REQUEST_TEMPLATES[key].workflowType,
      title: REQUEST_TEMPLATES[key].title,
      summary: REQUEST_TEMPLATES[key].summary,
    })),
  };
}

function appendAudit(request, type, actor, detail) {
  request.auditTrail.unshift({
    id: crypto.randomUUID(),
    type,
    actor,
    detail,
    createdAt: new Date().toISOString(),
  });
}

function createRequestFromTemplate(templateKey) {
  const template = REQUEST_TEMPLATES[templateKey];

  if (!template) {
    const error = new Error('Unknown request template');
    error.status = 400;
    throw error;
  }

  const state = readStore();
  const id = `VR-${Math.floor(Math.random() * 9000) + 1000}`;
  const request = {
    id,
    ...clone(template),
    status: 'awaiting_verification',
    openedAt: new Date().toISOString(),
    verificationChallenges: [],
    approvals: [],
    auditTrail: [],
  };

  appendAudit(request, 'request_opened', 'System', `${request.title} created from ${request.sourceSystem}.`);
  appendAudit(request, 'policy_hit', 'Policy Engine', `Applied ${request.policyIds.length} policy rule(s) to this request.`);

  state.requests.unshift(request);
  writeStore(state);

  return responsePayload(state, id);
}

function transitionAfterVerification(request) {
  if (request.requiredApprovalRoles.length > 0) {
    request.status = 'awaiting_approval';
  } else {
    request.status = 'verified';
  }
}

function handleVerification(request, payload) {
  const methodType = payload.methodType;
  const outcome = payload.outcome;

  if (!methodType || !['passed', 'failed'].includes(outcome)) {
    const error = new Error('Verification action requires a method type and outcome');
    error.status = 400;
    throw error;
  }

  request.verificationChallenges.unshift({
    id: crypto.randomUUID(),
    methodType,
    status: outcome,
    performedBy: payload.actor || 'Operator',
    note: payload.note || '',
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
  });

  if (outcome === 'passed') {
    transitionAfterVerification(request);
    appendAudit(request, 'verification_passed', payload.actor || 'Operator', `${methodType} verification passed.`);
  } else {
    request.status = 'denied';
    appendAudit(request, 'request_denied', payload.actor || 'Operator', `${methodType} verification failed.`);
  }
}

function handleApproval(state, request, payload) {
  const approver = state.teamDirectory.find((member) => member.id === payload.approverId);
  const decision = payload.decision;
  const passedChallenges = request.verificationChallenges.filter((challenge) => challenge.status === 'passed').length;

  if (!approver || !['approved', 'denied'].includes(decision)) {
    const error = new Error('Approval action requires a valid approver and decision');
    error.status = 400;
    throw error;
  }

  if (decision === 'approved' && request.verificationOptions.length > 0 && passedChallenges === 0) {
    const error = new Error('Record a verification proof before approving this request');
    error.status = 400;
    throw error;
  }

  request.approvals.unshift({
    id: crypto.randomUUID(),
    approverId: approver.id,
    approverName: approver.name,
    approverRole: approver.role,
    decision,
    rationale: payload.rationale || '',
    createdAt: new Date().toISOString(),
  });

  if (decision === 'denied') {
    request.status = 'denied';
    appendAudit(request, 'request_denied', approver.name, `${approver.role} denied the request.`);
    return;
  }

  const approvedRoles = new Set(
    request.approvals.filter((approval) => approval.decision === 'approved').map((approval) => approval.approverRole),
  );
  const approvalsSatisfied = request.requiredApprovalRoles.every((role) => approvedRoles.has(role));

  request.status = approvalsSatisfied ? 'verified' : 'awaiting_approval';
  appendAudit(request, 'approval_recorded', approver.name, `${approver.role} approved the request.`);
}

function handleEscalation(request, payload) {
  request.status = 'awaiting_approval';
  appendAudit(
    request,
    'request_escalated',
    payload.actor || 'Operator',
    payload.note || 'Request escalated for manual approval.',
  );
}

function applyAction(requestId, action) {
  const state = readStore();
  const request = state.requests.find((item) => item.id === requestId);

  if (!request) {
    const error = new Error('Request not found');
    error.status = 404;
    throw error;
  }

  switch (action.type) {
    case 'run_verification':
      handleVerification(request, action.payload || {});
      break;
    case 'approval_decision':
      handleApproval(state, request, action.payload || {});
      break;
    case 'escalate_request':
      handleEscalation(request, action.payload || {});
      break;
    default: {
      const error = new Error('Unsupported action type');
      error.status = 400;
      throw error;
    }
  }

  writeStore(state);
  return responsePayload(state, requestId);
}

function resetStore() {
  const state = buildSeedState();
  writeStore(state);
  return responsePayload(state);
}

function getDashboard(requestId) {
  const state = readStore();
  return responsePayload(state, requestId);
}

module.exports = {
  applyAction,
  createRequestFromTemplate,
  getDashboard,
  resetStore,
};
