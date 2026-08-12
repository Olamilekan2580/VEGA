const crypto = require('crypto');
const { readState, storageModeLabel, writeState } = require('./stateStore');

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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function timestampMinutesAgo(minutesAgo) {
  return new Date(Date.now() - minutesAgo * 60 * 1000).toISOString();
}

function uuid() {
  return crypto.randomUUID();
}

function randomSecret(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

function passwordDigest(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function newPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, digest: passwordDigest(password, salt) };
}

function verifyPassword(password, passwordRecord) {
  return passwordDigest(password, passwordRecord.salt) === passwordRecord.digest;
}

function newAudit(type, actor, detail, createdAt = new Date().toISOString()) {
  return { id: uuid(), type, actor, detail, createdAt };
}

function buildConnectors() {
  return {
    servicenow: {
      id: 'connector-servicenow',
      provider: 'ServiceNow',
      type: 'service_desk',
      status: 'Pilot',
      enabled: true,
      secret: randomSecret('vega'),
      inboundPath: '/api/connectors/servicenow/events',
      description: 'Create VegaVerify requests from ServiceNow or any help-desk workflow via a signed webhook.',
      lastEventAt: null,
      fieldMapping: [
        'templateKey',
        'requestedBy',
        'subjectName',
        'summary',
        'requestedAction',
        'amountAtRisk',
      ],
    },
  };
}

function seededRequests() {
  return [
    {
      id: 'VR-2401',
      ...clone(REQUEST_TEMPLATES.account_recovery),
      status: 'awaiting_verification',
      openedAt: timestampMinutesAgo(14),
      verificationChallenges: [],
      approvals: [],
      auditTrail: [
        newAudit('request_opened', 'System', 'Request created from Okta Help Desk.', timestampMinutesAgo(14)),
        newAudit(
          'policy_hit',
          'Policy Engine',
          'Admin Recovery Lock required phishing-resistant verification.',
          timestampMinutesAgo(13),
        ),
      ],
    },
    {
      id: 'VR-2402',
      ...clone(REQUEST_TEMPLATES.vendor_change),
      status: 'awaiting_approval',
      openedAt: timestampMinutesAgo(33),
      verificationChallenges: [
        {
          id: uuid(),
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
        newAudit(
          'request_opened',
          'System',
          'Vendor change request imported from NetSuite AP Queue.',
          timestampMinutesAgo(33),
        ),
        newAudit(
          'verification_passed',
          'Nadia Brooks',
          'Verified callback completed successfully.',
          timestampMinutesAgo(25),
        ),
      ],
    },
    {
      id: 'VR-2403',
      ...clone(REQUEST_TEMPLATES.payroll_change),
      status: 'denied',
      openedAt: timestampMinutesAgo(58),
      verificationChallenges: [
        {
          id: uuid(),
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
        newAudit('request_opened', 'System', 'Payroll change request imported from Workday.', timestampMinutesAgo(58)),
        newAudit(
          'request_denied',
          'Owen Hale',
          'Known-channel verification failed. Request blocked.',
          timestampMinutesAgo(49),
        ),
      ],
    },
    {
      id: 'VR-2404',
      ...clone(REQUEST_TEMPLATES.account_recovery),
      requestedBy: 'Priya Moore',
      subjectName: 'Lila Chen',
      assignedTeam: 'IT Support',
      targetSystem: 'ServiceNow Linked Account',
      requestedAction: 'Reset standard account password',
      summary: 'User called in from a known device and completed callback verification.',
      riskScore: 66,
      priority: 'Medium',
      status: 'verified',
      openedAt: timestampMinutesAgo(95),
      verificationOptions: ['verified_callback'],
      requiredApprovalRoles: [],
      verificationChallenges: [
        {
          id: uuid(),
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
        newAudit('request_opened', 'System', 'Reset request created from ServiceNow.', timestampMinutesAgo(95)),
        newAudit(
          'verification_passed',
          'Nadia Brooks',
          'Callback verification passed and request released.',
          timestampMinutesAgo(89),
        ),
      ],
    },
  ];
}

function buildOrgWorkspace(name) {
  return {
    organizationProfile: {
      name,
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
        status: 'Pilot',
        coverage: 'Inbound help-desk events routed into VegaVerify.',
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
    connectors: buildConnectors(),
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
      retention: 'Audit events retained for 180 days',
      notifications: 'Email and Slack notifications enabled for all high-risk requests',
      storageMode: storageModeLabel(),
    },
    policyPack: clone(POLICY_PACK),
    teamDirectory: clone(TEAM_DIRECTORY),
    requests: seededRequests(),
  };
}

function buildInitialState() {
  return {
    meta: {
      productName: 'VegaVerify',
      version: 2,
      refreshedAt: new Date().toISOString(),
    },
    users: [],
    organizations: [],
    sessions: [],
  };
}

async function readStore() {
  const state = await readState(buildInitialState);
  state.organizations = (state.organizations || []).map((organization) => ({
    ...organization,
    invitations: organization.invitations || [],
    workspace: {
      ...buildOrgWorkspace(organization.workspace?.organizationProfile?.name || 'Vega Workspace'),
      ...organization.workspace,
      connectors: {
        ...buildConnectors(),
        ...(organization.workspace?.connectors || {}),
      },
    },
  }));
  return state;
}

async function writeStoreSafe(state) {
  state.meta.refreshedAt = new Date().toISOString();
  await writeState(state);
}

function publicUser(user) {
  return {
    id: user.id,
    organizationId: user.organizationId,
    name: user.name,
    email: user.email,
    role: user.role,
  };
}

function publicInvitation(invitation) {
  return {
    id: invitation.id,
    email: invitation.email,
    name: invitation.name,
    role: invitation.role,
    inviteCode: invitation.inviteCode,
    status: invitation.status,
    createdAt: invitation.createdAt,
  };
}

function getOrganization(state, organizationId) {
  return state.organizations.find((organization) => organization.id === organizationId);
}

function getOrganizationByConnectorSecret(state, secret) {
  return state.organizations.find((organization) => organization.workspace.connectors.servicenow.secret === secret);
}

function buildSessionPayload(user, token) {
  return { token, user: publicUser(user) };
}

function authenticate(state, token) {
  if (!token) {
    const error = new Error('Unauthorized');
    error.status = 401;
    throw error;
  }

  const session = state.sessions.find((item) => item.token === token);
  if (!session) {
    const error = new Error('Unauthorized');
    error.status = 401;
    throw error;
  }

  const user = state.users.find((item) => item.id === session.userId);
  if (!user) {
    const error = new Error('Unauthorized');
    error.status = 401;
    throw error;
  }

  return user;
}

function issueSession(state, user) {
  const token = crypto.randomBytes(24).toString('hex');
  state.sessions = state.sessions.filter((session) => session.userId !== user.id);
  state.sessions.push({
    id: uuid(),
    userId: user.id,
    token,
    createdAt: new Date().toISOString(),
  });
  return buildSessionPayload(user, token);
}

async function bootstrapAuth(token) {
  const state = await readStore();
  let session = null;

  if (token) {
    try {
      const user = authenticate(state, token);
      session = buildSessionPayload(user, token);
    } catch (error) {
      session = null;
    }
  }

  return {
    hasUsers: state.users.length > 0,
    session,
    brand: state.meta.productName,
  };
}

async function signUp({ name, email, password, organizationName }) {
  if (!name || !email || !password || !organizationName) {
    const error = new Error('name, email, password, and organizationName are required');
    error.status = 400;
    throw error;
  }

  const normalizedEmail = email.trim().toLowerCase();
  const state = await readStore();

  if (state.users.some((user) => user.email === normalizedEmail)) {
    const error = new Error('A user with that email already exists');
    error.status = 409;
    throw error;
  }

  const organizationId = uuid();
  const userId = uuid();

  state.organizations.push({
    id: organizationId,
    createdAt: new Date().toISOString(),
    invitations: [],
    workspace: buildOrgWorkspace(organizationName.trim()),
  });

  const user = {
    id: userId,
    organizationId,
    name: name.trim(),
    email: normalizedEmail,
    role: 'Owner',
    password: newPasswordRecord(password),
    createdAt: new Date().toISOString(),
  };

  state.users.push(user);
  const session = issueSession(state, user);
  await writeStoreSafe(state);
  return session;
}

async function signIn({ email, password }) {
  if (!email || !password) {
    const error = new Error('email and password are required');
    error.status = 400;
    throw error;
  }

  const normalizedEmail = email.trim().toLowerCase();
  const state = await readStore();
  const user = state.users.find((item) => item.email === normalizedEmail);

  if (!user || !verifyPassword(password, user.password)) {
    const error = new Error('Invalid email or password');
    error.status = 401;
    throw error;
  }

  const session = issueSession(state, user);
  await writeStoreSafe(state);
  return session;
}

async function acceptInvite({ inviteCode, name, password }) {
  if (!inviteCode || !name || !password) {
    const error = new Error('inviteCode, name, and password are required');
    error.status = 400;
    throw error;
  }

  const state = await readStore();
  const organization = state.organizations.find((item) =>
    item.invitations.some((invitation) => invitation.inviteCode === inviteCode && invitation.status === 'pending'),
  );

  if (!organization) {
    const error = new Error('Invite not found or already used');
    error.status = 404;
    throw error;
  }

  const invitation = organization.invitations.find(
    (item) => item.inviteCode === inviteCode && item.status === 'pending',
  );

  if (state.users.some((user) => user.email === invitation.email)) {
    const error = new Error('That invited email already has an account');
    error.status = 409;
    throw error;
  }

  const user = {
    id: uuid(),
    organizationId: organization.id,
    name: name.trim(),
    email: invitation.email,
    role: invitation.role,
    password: newPasswordRecord(password),
    createdAt: new Date().toISOString(),
  };

  invitation.status = 'accepted';
  invitation.acceptedAt = new Date().toISOString();
  state.users.push(user);
  const session = issueSession(state, user);
  await writeStoreSafe(state);
  return session;
}

async function signOut(token) {
  const state = await readStore();
  state.sessions = state.sessions.filter((session) => session.token !== token);
  await writeStoreSafe(state);
}

function requireWorkspace(state, token) {
  const user = authenticate(state, token);
  const organization = getOrganization(state, user.organizationId);
  return { user, organization, workspace: organization.workspace };
}

function getPolicyById(workspace, policyId) {
  return workspace.policyPack.find((policy) => policy.id === policyId);
}

function hydrateRequest(workspace, request) {
  return {
    ...request,
    policyPack: request.policyIds.map((policyId) => getPolicyById(workspace, policyId)).filter(Boolean),
    completedApprovals: request.approvals.filter((approval) => approval.decision === 'approved').length,
    requiredApprovals: request.requiredApprovalRoles.length,
    verificationProgress: {
      passed: request.verificationChallenges.filter((challenge) => challenge.status === 'passed').length,
      failed: request.verificationChallenges.filter((challenge) => challenge.status === 'failed').length,
    },
  };
}

function sortedRequests(workspace) {
  return workspace.requests
    .slice()
    .sort((left, right) => new Date(right.openedAt).getTime() - new Date(left.openedAt).getTime())
    .map((request) => hydrateRequest(workspace, request));
}

function summarize(workspace) {
  const requests = sortedRequests(workspace);
  const activeRequests = requests.filter((request) => ['awaiting_verification', 'awaiting_approval'].includes(request.status));
  const blockedRequests = requests.filter((request) => request.status === 'denied');
  const verifiedRequests = requests.filter((request) => request.status === 'verified');
  const approvalQueue = requests.filter((request) => request.status === 'awaiting_approval');

  return {
    organizationName: workspace.organizationProfile.name,
    environment: 'workspace',
    refreshedAt: new Date().toISOString(),
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
        value: `$${activeRequests.reduce((sum, request) => sum + request.amountAtRisk, 0).toLocaleString()}`,
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

function activityFeed(workspace) {
  return workspace.requests
    .flatMap((request) =>
      request.auditTrail.map((event) => ({
        ...event,
        requestId: request.id,
        title: request.title,
      })),
    )
    .sort((left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime())
    .slice(0, 12);
}

function workspacePayload(state, user, organization, focusRequestId) {
  const workspace = organization.workspace;
  const requests = sortedRequests(workspace);
  const selectedRequest = focusRequestId ? requests.find((request) => request.id === focusRequestId) : requests[0] || null;
  const members = state.users
    .filter((member) => member.organizationId === organization.id)
    .map((member) => publicUser(member));
  const invitations = organization.invitations.filter((invitation) => invitation.status === 'pending').map(publicInvitation);

  return {
    summary: summarize(workspace),
    requests,
    selectedRequest,
    organizationProfile: workspace.organizationProfile,
    integrations: workspace.integrations,
    connectors: Object.values(workspace.connectors),
    settings: workspace.settings,
    policyPack: workspace.policyPack,
    teamDirectory: workspace.teamDirectory,
    members,
    invitations,
    activityFeed: activityFeed(workspace),
    platform: {
      brand: state.meta.productName,
      storageMode: workspace.settings.storageMode,
    },
    templates: Object.keys(REQUEST_TEMPLATES).map((key) => ({
      key,
      workflowType: REQUEST_TEMPLATES[key].workflowType,
      title: REQUEST_TEMPLATES[key].title,
      summary: REQUEST_TEMPLATES[key].summary,
    })),
  };
}

async function getWorkspaceForToken(token, focusRequestId) {
  const state = await readStore();
  const { user, organization } = requireWorkspace(state, token);
  return {
    session: buildSessionPayload(user, token),
    workspace: workspacePayload(state, user, organization, focusRequestId),
  };
}

function buildRequestFromTemplate(templateKey, overrides = {}) {
  const template = REQUEST_TEMPLATES[templateKey];
  if (!template) {
    const error = new Error('Unknown request template');
    error.status = 400;
    throw error;
  }

  return {
    id: `VR-${Math.floor(Math.random() * 9000) + 1000}`,
    ...clone(template),
    ...overrides,
    status: 'awaiting_verification',
    openedAt: new Date().toISOString(),
    verificationChallenges: [],
    approvals: [],
    auditTrail: [],
  };
}

function createRequest(workspace, templateKey, overrides = {}) {
  const request = buildRequestFromTemplate(templateKey, overrides);
  request.auditTrail.unshift(newAudit('request_opened', 'System', `${request.title} created from ${request.sourceSystem}.`));
  request.auditTrail.unshift(
    newAudit('policy_hit', 'Policy Engine', `Applied ${request.policyIds.length} policy rule(s) to this request.`),
  );
  workspace.requests.unshift(request);
  return request.id;
}

function applyVerification(request, payload) {
  request.verificationChallenges.unshift({
    id: uuid(),
    methodType: payload.methodType,
    status: payload.outcome,
    performedBy: payload.actor || 'Operator',
    note: payload.note || '',
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
  });

  if (payload.outcome === 'passed') {
    request.status = request.requiredApprovalRoles.length ? 'awaiting_approval' : 'verified';
    request.auditTrail.unshift(
      newAudit('verification_passed', payload.actor || 'Operator', `${payload.methodType} verification passed.`),
    );
  } else {
    request.status = 'denied';
    request.auditTrail.unshift(
      newAudit('request_denied', payload.actor || 'Operator', `${payload.methodType} verification failed.`),
    );
  }
}

function applyApproval(teamDirectory, request, payload) {
  const approver = teamDirectory.find((member) => member.id === payload.approverId);
  if (!approver) {
    const error = new Error('Approval action requires a valid approver');
    error.status = 400;
    throw error;
  }

  request.approvals.unshift({
    id: uuid(),
    approverId: approver.id,
    approverName: approver.name,
    approverRole: approver.role,
    decision: payload.decision,
    rationale: payload.rationale || '',
    createdAt: new Date().toISOString(),
  });

  if (payload.decision === 'denied') {
    request.status = 'denied';
    request.auditTrail.unshift(newAudit('request_denied', approver.name, `${approver.role} denied the request.`));
    return;
  }

  const approvedRoles = new Set(
    request.approvals.filter((approval) => approval.decision === 'approved').map((approval) => approval.approverRole),
  );
  request.status = request.requiredApprovalRoles.every((role) => approvedRoles.has(role)) ? 'verified' : 'awaiting_approval';
  request.auditTrail.unshift(newAudit('approval_recorded', approver.name, `${approver.role} approved the request.`));
}

function actOnRequest(workspace, requestId, action) {
  const request = workspace.requests.find((item) => item.id === requestId);
  if (!request) {
    const error = new Error('Request not found');
    error.status = 404;
    throw error;
  }

  if (action.type === 'run_verification') {
    applyVerification(request, action.payload || {});
  } else if (action.type === 'approval_decision') {
    applyApproval(workspace.teamDirectory, request, action.payload || {});
  } else {
    const error = new Error('Unsupported action type');
    error.status = 400;
    throw error;
  }
}

async function updateOrganization(token, updates) {
  const state = await readStore();
  const { user, organization, workspace } = requireWorkspace(state, token);
  const profile = workspace.organizationProfile;

  profile.name = updates.name?.trim() || profile.name;
  profile.industry = updates.industry?.trim() || profile.industry;
  profile.workforceSize = updates.workforceSize?.trim() || profile.workforceSize;
  profile.primaryIdp = updates.primaryIdp?.trim() || profile.primaryIdp;
  profile.financeSystem = updates.financeSystem?.trim() || profile.financeSystem;
  profile.supportPlatform = updates.supportPlatform?.trim() || profile.supportPlatform;
  profile.riskPosture = updates.riskPosture?.trim() || profile.riskPosture;

  await writeStoreSafe(state);
  return {
    session: buildSessionPayload(user, token),
    workspace: workspacePayload(state, user, organization),
  };
}

async function resetWorkspace(token) {
  const state = await readStore();
  const { user, organization } = requireWorkspace(state, token);
  organization.workspace = buildOrgWorkspace(organization.workspace.organizationProfile.name);
  await writeStoreSafe(state);
  return {
    session: buildSessionPayload(user, token),
    workspace: workspacePayload(state, user, organization),
  };
}

async function inviteMember(token, payload) {
  if (!payload.email || !payload.name || !payload.role) {
    const error = new Error('email, name, and role are required');
    error.status = 400;
    throw error;
  }

  const state = await readStore();
  const { user, organization } = requireWorkspace(state, token);
  const normalizedEmail = payload.email.trim().toLowerCase();

  if (state.users.some((member) => member.email === normalizedEmail && member.organizationId === organization.id)) {
    const error = new Error('That user is already a member of this workspace');
    error.status = 409;
    throw error;
  }

  if (organization.invitations.some((invitation) => invitation.email === normalizedEmail && invitation.status === 'pending')) {
    const error = new Error('That user already has a pending invitation');
    error.status = 409;
    throw error;
  }

  organization.invitations.unshift({
    id: uuid(),
    email: normalizedEmail,
    name: payload.name.trim(),
    role: payload.role.trim(),
    inviteCode: randomSecret('invite'),
    invitedBy: user.id,
    status: 'pending',
    createdAt: new Date().toISOString(),
  });

  await writeStoreSafe(state);
  return {
    session: buildSessionPayload(user, token),
    workspace: workspacePayload(state, user, organization),
  };
}

async function updateServiceNowConnector(token, updates) {
  const state = await readStore();
  const { user, organization, workspace } = requireWorkspace(state, token);
  const connector = workspace.connectors.servicenow;

  if (typeof updates.enabled === 'boolean') {
    connector.enabled = updates.enabled;
  }

  if (updates.status) {
    connector.status = updates.status;
  }

  if (updates.description?.trim()) {
    connector.description = updates.description.trim();
  }

  await writeStoreSafe(state);
  return {
    session: buildSessionPayload(user, token),
    workspace: workspacePayload(state, user, organization),
  };
}

async function rotateServiceNowSecret(token) {
  const state = await readStore();
  const { user, organization, workspace } = requireWorkspace(state, token);
  workspace.connectors.servicenow.secret = randomSecret('vega');
  await writeStoreSafe(state);
  return {
    session: buildSessionPayload(user, token),
    workspace: workspacePayload(state, user, organization),
  };
}

async function mutateWorkspace(token, mutation) {
  const state = await readStore();
  const { user, organization, workspace } = requireWorkspace(state, token);
  let focusRequestId = mutation.focusRequestId || '';

  if (mutation.type === 'create_request') {
    focusRequestId = createRequest(workspace, mutation.templateKey);
  } else if (mutation.type === 'request_action') {
    actOnRequest(workspace, mutation.requestId, mutation.action);
    focusRequestId = mutation.requestId;
  } else {
    const error = new Error('Unsupported workspace mutation');
    error.status = 400;
    throw error;
  }

  await writeStoreSafe(state);
  return {
    session: buildSessionPayload(user, token),
    workspace: workspacePayload(state, user, organization, focusRequestId),
  };
}

async function ingestServiceNowEvent(secret, payload) {
  if (!secret) {
    const error = new Error('Missing connector secret');
    error.status = 401;
    throw error;
  }

  const state = await readStore();
  const organization = getOrganizationByConnectorSecret(state, secret);

  if (!organization) {
    const error = new Error('Connector not found');
    error.status = 404;
    throw error;
  }

  const connector = organization.workspace.connectors.servicenow;
  if (!connector.enabled) {
    const error = new Error('Connector is disabled');
    error.status = 403;
    throw error;
  }

  const templateKey = payload.templateKey || 'account_recovery';
  const requestId = createRequest(organization.workspace, templateKey, {
    sourceSystem: 'ServiceNow Connector',
    requestedBy: payload.requestedBy || 'Service desk automation',
    subjectName: payload.subjectName || 'Imported request',
    summary: payload.summary || REQUEST_TEMPLATES[templateKey].summary,
    requestedAction: payload.requestedAction || REQUEST_TEMPLATES[templateKey].requestedAction,
    amountAtRisk: Number(payload.amountAtRisk || REQUEST_TEMPLATES[templateKey].amountAtRisk || 0),
  });

  const request = organization.workspace.requests.find((item) => item.id === requestId);
  request.auditTrail.unshift(
    newAudit('connector_ingest', 'ServiceNow Connector', 'Inbound ServiceNow event created a protected request.'),
  );
  connector.lastEventAt = new Date().toISOString();
  await writeStoreSafe(state);

  return {
    requestId,
    connector: connector.provider,
    organization: organization.workspace.organizationProfile.name,
  };
}

module.exports = {
  acceptInvite,
  bootstrapAuth,
  getWorkspaceForToken,
  ingestServiceNowEvent,
  inviteMember,
  mutateWorkspace,
  resetWorkspace,
  rotateServiceNowSecret,
  signIn,
  signOut,
  signUp,
  updateOrganization,
  updateServiceNowConnector,
};
