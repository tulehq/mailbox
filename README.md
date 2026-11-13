# mailbox

An Amazon SES v2-compatible mail service that never delivers mail. Every
message it accepts is stored, as a recipient would receive it, in a local
SQLite database, and a retrieval API lists, searches, reads back and deletes
what was sent. It is built to stand in for SES in local development and
end-to-end tests: point an AWS SDK, or anything that sends through SES v2, at
it, and then ask it what your code sent.

It is not a mail server. No message leaves it, and no identity is ever
verified (every identity counts as verified at once). The configured access
key can send and read every message; when it is pointed at
[identity](https://github.com/tulehq/identity), the keys identity issued are
accepted too, and each is held to its IAM identity policies
([Permissions](#permissions)).

## Running it

With Docker:

```sh
docker run --rm -p 9040:9040 -v mailboxdata:/data \
  -e TULE_Auth_AccessKeyID=test -e TULE_Auth_SecretAccessKey=test \
  ghcr.io/tulehq/mailbox:latest
```

The image is based on Alpine, so `docker exec -it <container> sh` gives you a
shell. It runs as the unprivileged `nonroot` user, keeps its database at
`/data/mailbox.db` on the `/data` volume, and its Docker health check polls
`/_ready`.

From source (Go 1.27.4 or later):

```sh
make build
TULE_Auth_AccessKeyID=test TULE_Auth_SecretAccessKey=test ./build/tule-mailbox
```

It listens on port 9040, so it does not collide with
[object-store](https://github.com/tulehq/object-store) on 9000,
[secret-store](https://github.com/tulehq/secret-store) on 9010,
[accounts](https://github.com/tulehq/accounts) on 9020 or
[identity](https://github.com/tulehq/identity) on 9030.

## Configuration

Settings come from environment variables prefixed with `TULE_`, and from a
`.env` file in the working directory (without the prefix).

| Variable | Default | Purpose |
|---|---|---|
| `TULE_Server_Port` | `9040` | Listen port |
| `TULE_Store_Path` | `./data/mailbox.db` (`/data/mailbox.db` in the image) | The SQLite database file; it and its directory are created if missing |
| `TULE_HSTS_MaxAge` | unset | `Strict-Transport-Security` max age; the header is only sent when set |
| `TULE_Server_ReadTimeout` | `60s` | How long the server may take to read a request, body included |
| `TULE_Server_ReadHeaderTimeout` | `30s` | How long it may take to read a request's headers; must be positive |
| `TULE_Server_WriteTimeout` | `60s` | How long it may take to write a response |
| `TULE_Server_IdleTimeout` | `2m` | How long a keep-alive connection may sit idle between requests |
| `TULE_Server_ShutdownTimeout` | `7s` | How long a graceful shutdown waits for in-flight requests |
| `TULE_Auth_AccessKeyID` | required | The access key clients sign requests with |
| `TULE_Auth_SecretAccessKey` | required | Its secret |
| `TULE_Auth_IdentityEndpoint` | unset | The identity service's base URL, such as `http://localhost:9030`: an absolute http or https URL. Set, the keys identity issued are accepted as well as the configured key, held to their identity policies ([Permissions](#permissions)), the principals of stored sending authorization policies are bound to unique IDs ([Sending authorization](#sending-authorization)), and identity is asked about them with the configured key, which must be identity's root key. Identity 0.5.0 or later is required. Unset, mailbox runs standalone on the configured key alone |
| `TULE_Mailbox_AccountID` | `000000000000` | The account mailbox's resources belong to: 12 digits. The root key acts in it and the ARNs carry it; a principal of any other account needs an email identity's sending authorization policy as well as its own identity policy (see Sending authorization). The default is identity's default management account |
| `TULE_Mailbox_Region` | `us-east-1` | The region the ARNs carry and `aws:RequestedRegion` is, whatever region a request was signed for |
| `TULE_GasEnv` | | `development` logs console output at trace level, `production` logs at warn level, `testing` disables logging |

The read and write timeouts are sized for the largest request this service
accepts, a 64 MiB body: a message at SES's 40 MB limit, base64-encoded in
JSON. Logs go to the console only; there is no log shipping.

The server refuses to start without an access key, because every request is
verified against it and any web page the developer has open can reach a server
on localhost.

With an identity endpoint, a request signed with any key but the configured
one is verified through identity's signing-key endpoint, on every request:
a key identity deactivates or deletes is refused on the next one. A request
signed with the configured key never asks identity. When identity cannot be
asked, fails, or gives no answer within 10 seconds, a request signed with
another key fails with `500` `InternalFailure`, never as an unknown key,
and the configured key keeps working.

## Permissions

Without an identity endpoint nothing is evaluated: the configured key is the
account's root, and may call everything.

With one, mailbox authorizes requests as AWS does, within an account and
across accounts, with [tule.dev/policy](https://github.com/tulehq/policy)'s
`Authorize`:

- **The root principal of mailbox's account** (`TULE_Mailbox_AccountID`) is
  always allowed and never evaluated against policies: the configured key,
  which is also identity's root user's key.
- **Every other principal**, an IAM user's key, a role session's, or the root
  user of another account, is evaluated on every request, the SES API's and
  the retrieval API's, against the identity policies identity reports for it
  (a user's inline and attached managed policies, or a session's role's) and
  the resource-based policies of what it acts on. Only an identity's sending
  authorization policies are resource-based policies here, and only sends
  are evaluated with them ([Sending authorization](#sending-authorization));
  every other operation, and the retrieval API, has none.
- **How they combine** is the IAM User Guide's ("Policy evaluation logic",
  "Cross-account policy evaluation logic"): an explicit `Deny` in either kind
  denies. Within mailbox's account an `Allow` in either kind allows, but a
  resource-based `Allow` that names the caller only through its account (the
  account ID or `arn:aws:iam::<account>:root`) delegates to the account and
  also needs an identity `Allow`; one that names the IAM user, the role (by its
  ARN, path included) or the session, or `"*"`, is enough alone. A principal
  of another account needs both an identity `Allow` and a resource-based
  `Allow` of any kind; another account's root user has full identity access
  to its own account, so it needs only the resource-based one.
- **A denied request** fails with `AccessDeniedException`, `403` (the SES v2
  Common Errors page; the SDK model does not define it, so the SDK reports it
  as a generic API error), with AWS's message "User: \<arn\> is not authorized
  to perform: \<action\> on resource: \<arn\> \<reason\>", the reason being
  `policy.Reason`'s message: "with an explicit deny in an identity-based
  policy", "with an explicit deny in a resource-based policy", "because no
  identity-based policy allows the \<action\> action" or "because no
  resource-based policy allows the \<action\> action"
  (IAM User Guide, "Troubleshoot access denied error messages"; SES
  documents no wording of its own). When both kinds deny, the identity-based
  one is named; a request no policy allows within the account names the
  identity-based kind. Nothing is stored for a denied request.
- **Fail closed.** A principal whose attributes disagree (its type, ARN,
  `PrincipalArn` and unique ID, as tule.dev/policy checks them) or a role
  session whose role was deleted (an empty `PrincipalArn`) is denied with
  "... because no identity-based policy allows ...". A principal marked
  `Root` that is not of type `Account`, or one of type `Account` not marked
  `Root`, is refused with `500` `InternalFailure` and logged, in mailbox's
  own account too: the check runs before the root's shortcut, since `Root`
  skips evaluation and `Account` grants full identity access. identity keeps
  the two in step, and mailbox's configured key is built with the account's
  root ARN, so its type is `Account`; a principal on which they disagree is
  a fault. A
  stored policy that no longer parses also fails its request with `500`.

**This was a breaking change in 0.2.** A key identity issued used to be able
to call everything; one with no policy is now denied everything. Give it a
policy, such as `{"Effect": "Allow", "Action": ["ses:*", "tule:Inspect"],
"Resource": "*"}` for the access it had.

### Actions and resources

Each operation is evaluated as its action and on its resources from the
Service Authorization Reference for SES (the service reference JSON,
<https://servicereference.us-east-1.amazonaws.com/v1/ses/ses.json>, v1.5, a
copy of which is in `internal/authz/testdata`), with the reference's ARN
formats: `arn:aws:ses:<region>:<account>:identity/<name>`,
`configuration-set/<name>` and `template/<name>`. The account and region are
mailbox's, `TULE_Mailbox_AccountID` and `TULE_Mailbox_Region`, never the
request's: every signed region verifies, so a caller could otherwise pick
the region a `Deny` names. One store serves every region. A send's `TemplateArn` must be an SES template ARN
(`BadRequestException` otherwise); one of another account or region names
no template mailbox holds, and is answered with `NotFoundException` before
anything is evaluated, since SES documents no answer for it. The send is
evaluated on the template's ARN rebuilt from mailbox's account and
region and the name, never on the string sent. The table is
[`internal/authz/operations.go`](internal/authz/operations.go), and a test
holds every route to an entry and every entry to the reference.

| Operation | Action | Evaluated on |
|---|---|---|
| `SendEmail` | `ses:SendEmail` | The sender's identity, and for `Raw` content with a `From` header and `FromEmailAddress` the header's identity too; the `FeedbackForwardingEmailAddress`'s identity, when it has one; the configuration set, when the request (or a raw message's `X-SES-CONFIGURATION-SET` header) names one; the stored template, for `Template` content that names one |
| `SendBulkEmail` | `ses:SendBulkEmail` | The same, from the request. They are shared by every entry, so a denial refuses the whole request, as `BulkEmailStatus` has no access-denied status |
| `CreateEmailIdentity` | `ses:CreateEmailIdentity`, and `ses:TagResource` when it has `Tags` | The new identity |
| `GetEmailIdentity`, `DeleteEmailIdentity` | `ses:GetEmailIdentity`, `ses:DeleteEmailIdentity` | The identity |
| `CreateEmailIdentityPolicy`, `GetEmailIdentityPolicies`, `UpdateEmailIdentityPolicy`, `DeleteEmailIdentityPolicy` | `ses:<Operation>` | The identity |
| `ListEmailIdentities` | `ses:ListEmailIdentities` | `*` |
| `CreateEmailTemplate` | `ses:CreateEmailTemplate`, and `ses:TagResource` when it has `Tags` | The new template |
| `GetEmailTemplate`, `UpdateEmailTemplate`, `DeleteEmailTemplate`, `TestRenderEmailTemplate` | `ses:<Operation>` | The template |
| `ListEmailTemplates`, `GetAccount` | `ses:<Operation>` | `*` |
| The retrieval API, every route | `tule:Inspect` | `arn:aws:ses:<region>:<account>:*` |

`SendEmail` with `Raw` content is evaluated as `ses:SendEmail` alone. The
service reference maps the SES v2 `SendEmail` operation to `ses:SendEmail`
with no further authorized action, and lists `ses:SendRawEmail` for SES v1's
`SendRawEmail` only; the SES Developer Guide ("Controlling access") requires
`ses:SendRawEmail` for the SMTP interface, not for the v2 API.

A create with tags is also evaluated as `ses:TagResource`, as the reference's
Operations section lists it among the actions `CreateEmailIdentity` and
`CreateEmailTemplate` authorize. Each action is evaluated on each resource in
the order above, and the first that is not allowed is the one the error
names.

**The sender's identity.** mailbox sends from any address, with or without an
identity, so the identity a send is evaluated on is the most granular one
created that covers the address, as SES applies the settings of the most
granular identity verified and a verified domain covers its subdomains
(SES Developer Guide, "Creating and verifying identities"): the email
address identity, if one was created; else the address's domain, if
created; else its nearest parent domain that was created; else, with none
created, the address's domain. Which identity AWS evaluates when several
cover an address is not documented; this is the choice made here. So
`app@mail.example.com` is evaluated on `identity/app@mail.example.com`,
`identity/mail.example.com` or `identity/example.com`, whichever exists
first, and on `identity/mail.example.com` when none does.

The candidates skipped because they do not exist (with none created, every
candidate but the address's domain) are checked for an explicit `Deny` as
well, though not for an `Allow`: a `Deny` on `identity/example.com` refuses
`app@mail.example.com` whether or not any identity exists, so it cannot be
sidestepped through a subdomain no identity covers. A subdomain identity
that does exist is the one evaluated, as in AWS, and its parent's `Deny`
does not reach it.

Names are canonical, as SES compares them: "Domain names are
case-insensitive" and "Email addresses are case sensitive" (SES Developer
Guide, "Creating and verifying identities"). A domain identity is stored,
looked up and evaluated in lower case, so `a@Example.COM` is evaluated on
`identity/example.com`; an email address identity is kept as written,
domain part included, so `Sender@EXAMPLE.com` and `sender@example.com` are
two identities.

For `Raw` content without `FromEmailAddress` the sender is the message's
`From` header. With both, the header reaches the recipients as written, so
the send is evaluated on the identities of both, with `ses:FromAddress` and
`ses:FromDisplayName` taken from the header on the header's identity: SES
authorizes the `From` address in a raw message's header apart from its
envelope sender (SendRawEmail API reference, `FromArn`). A `From` header that
is not one valid address is then refused with `BadRequestException`.

**`tule:Inspect`** is not an AWS action: AWS has no API that reads back what
SES accepted. It is evaluated on the whole service in the caller's account and
region, `arn:aws:ses:<region>:<account>:*`, so it takes a grant of the
service, such as `"Resource": "*"` or `"arn:aws:ses:*:<account>:*"`, rather
than of one identity: every stored message, whoever sent it, is behind it.

### Condition keys

Every request supplies `aws:SourceIp` (the connection's peer address),
`aws:CurrentTime`, `aws:EpochTime`, `aws:SecureTransport`,
`aws:RequestedRegion` (`TULE_Mailbox_Region`, not the signed region) and
`aws:PrincipalTag/<key>` for each of the principal's tags. Principal tags
are the IAM user's or the role's: identity issues no session tags.
`aws:PrincipalOrgID` and `aws:PrincipalOrgPaths` are the organization and
the account's path in it (`o-.../r-.../ou-.../`, one path, as an account has
one parent), as identity reports them for a principal whose account is an
active member of the organization the accounts service knows, or its
management account; they are absent for any other principal, as AWS leaves
them out for an account in no organization. Identity keeps an account's
organization for up to 30 seconds, so an account moved or removed keeps
its old keys that long. When identity could not ask the accounts service,
both keys are evaluated as unknown (tule.dev/policy's `Unknown`), never as
absent: a condition on them then never helps an `Allow` apply and always
helps a `Deny` apply, so a negated condition such as `StringNotEquals`
neither grants nor lets a `Deny` lapse.
`policy.Authorize` supplies the principal's own keys from the attributes
identity reports (identity v0.5.0, signing-key version 4):
`aws:PrincipalArn` (a user's ARN, or a role session's role ARN with the
role's path, so `arn:aws:iam::*:role/restricted/*` matches a session of
`role/restricted/admin`), `aws:PrincipalAccount`, `aws:userid` (`AIDA...`,
or `AROA...:<session>`), `aws:PrincipalType` (`User`, `AssumedRole` or
`Account`) and, for an IAM user, `aws:username`. They fill policy variables
such as `${aws:username}` too, and the request cannot set them.

Each SES operation also supplies `ses:ApiVersion` (`2`), and the keys the
reference lists for it that mailbox has:

- `SendEmail`: `ses:FromAddress` (the sender's bare address),
  `ses:FromDisplayName` (its display name, when it has one), `ses:Recipients`
  (every To, Cc and Bcc address, bare) and `ses:FeedbackAddress`
  (`FeedbackForwardingEmailAddress`, when given). The reference lists none of
  these for `SendBulkEmail`, so it supplies none.
- `CreateEmailIdentity`, `CreateEmailTemplate` (and their `ses:TagResource`):
  `aws:RequestTag/<key>` and `aws:TagKeys` from `Tags`.
- `aws:ResourceTag/<key>`, from the stored tags of the identity or template a
  request is evaluated on, when it exists. Configuration sets are not stored
  and have no tags.

**Authorization and the operation read one decoding.** A request body is
decoded once, and the values an operation is authorized for are the values
it acts on: of duplicate JSON members, or members whose names differ only by
case, the last one, for both. In a raw message the first of repeated
`X-SES-CONFIGURATION-SET` and `X-SES-MESSAGE-TAGS` headers is the one used,
as SES documents for its X-headers, and a second `From` header is refused
with `MessageRejected` before anything reads the first.

**The resource evaluated is the resource acted on.** An operation looks up
the identities and templates it is evaluated on (for their tags, and a
send's identity for its name) and then acts on them under one lock: a
create, update or delete of an identity or template waits for the
operations in flight, so none can make an operation act on a resource other
than the one it was authorized for. No operation changes a resource's tags,
so they cannot go stale in between either.

Sending authorization policies are loaded the same way: with the sender's
identity, in one transaction, under the shared lock, and a policy create,
update or delete takes the lock exclusively. The policies a send is
evaluated with are its identity's when it is stored.

The request context is capped at 100 values per key and 1,024 bytes per value
(validation already holds a send to 50 recipients and a resource to 50 tags);
a request past the cap is refused with `BadRequestException` rather than
evaluated on part of it. Every value the request supplies is under that cap, the
sender's display names and addresses included. Resource names are bounded
too, before anything is evaluated, since matching costs a pattern's length
times the ARN's: an email address to 320 characters (RFC 5321's 64-octet
local part and 255-octet domain), a domain to 253, a configuration set name
to 64 (SES's quota) and a template name to 256 (SES gives no maximum; this
is mailbox's bound). A longer one is refused with `BadRequestException`. Parsed policies are cached by the SHA-256 of their
document, at most 512 of them.

### Sending authorization

An identity's sending authorization policies are resource-based policies
that let other principals send from it (SES Developer Guide, "Using
sending authorization"). They are served by the SES v2 operations:

| Operation | Behavior |
|---|---|
| `CreateEmailIdentityPolicy` | `POST /v2/email/identities/{EmailIdentity}/policies/{PolicyName}` with `{"Policy": "<document>"}`. `AlreadyExistsException` for a name the identity has, `LimitExceededException` past 20 policies, `NotFoundException` for an identity that does not exist |
| `GetEmailIdentityPolicies` | `GET /v2/email/identities/{EmailIdentity}/policies`: `{"Policies": {"<name>": "<document>"}}`. `NotFoundException` for an identity that does not exist |
| `UpdateEmailIdentityPolicy` | `PUT` at the create's path. A policy the identity does not have is not created, and the call succeeds |
| `DeleteEmailIdentityPolicy` | `DELETE` at the create's path. Succeeds for a policy the identity does not have |

`GetEmailIdentity` reports the policies too, and `DeleteEmailIdentity`
deletes them with the identity. Each is checked before it is stored,
`BadRequestException` otherwise (SES API v2 Reference, the four operations;
SES Developer Guide, "Policy anatomy"):

- the name is 1 to 64 letters, digits, dashes and underscores ("The policy
  name cannot exceed 64 characters and can only include alphanumeric
  characters, dashes, and underscores."), compared with its case;
- the document is at most 4 KB ("The policy cannot exceed 4 KB."), read as
  4,096 bytes;
- it parses with tule.dev/policy's `ParseResource`: JSON, every statement
  with a `Principal` or `NotPrincipal` and a valid principal (an account ID,
  a user, role or session ARN, a unique ID, `"*"`, or a service principal),
  no `Federated` principal, valid conditions. A `Sid` is any string unique
  within the policy, as the guide gives it ("Any string.", "Uniquely
  identifies the statement.");
- every statement's `Resource` is the identity's ARN, or that ARN with `*`
  for its region, as the guide's examples for a global endpoint have it
  ("that resource has to be the ARN of the identity that the policy is
  attached to"); `NotResource` is refused.

Every action is accepted in a document, though only a send is evaluated
with it.

**Principals are bound to unique IDs** when a policy is stored, as AWS
binds them ("If you delete the role, then you break the relationship. ...
The new role has a new principal ID that does not match the ID stored in
the policy", IAM User Guide, "AWS JSON policy elements: Principal"; the
same holds for users and for resource-based policies). With an identity
endpoint, `CreateEmailIdentityPolicy` and `UpdateEmailIdentityPolicy` ask
identity (its principal-ID endpoint, `tule.dev/identity/principals`) for
the unique ID of each IAM user and role ARN in the document's `Principal`
and `NotPrincipal`, and store the document with each such ARN replaced by
the `AIDA...` or `AROA...` ID of the IAM user or role that has it now; account
IDs, root ARNs, session ARNs, `"*"`, service principals and ARNs in
conditions are kept. A send is evaluated with the stored document, so a
user or role deleted and created again under the same name is another
principal, which the policy does not name, until the policy is saved again.
The rest of the document is kept as it was sent, its members in their
order, except the white space of an object in which an ID replaced an ARN.

- **A user or role that does not exist** is refused with
  `BadRequestException`, `Invalid policy: Invalid principal in policy:
  "AWS":"<arn>"`, the error the SES v2 reference gives for invalid
  input ("The input you provided is invalid."; SES documents no message, so
  the wording is mailbox's choice). It is reported only once the request
  is authorized: a caller that may not write the policy is denied whether or
  not the principals it names exist.
- **Reads show the policy as AWS shows it.** `GetEmailIdentityPolicies` and
  `GetEmailIdentity` ask identity for the current ARN of each unique ID: one
  whose user or role still exists is shown as its ARN, and one that no
  longer exists as the ID, as AWS shows it "because AWS can no longer map
  it back to a valid ARN".
- **Identity is asked outside the resource lock**, before a write takes it
  and after a read releases it, so a slow identity holds up no other
  operation; a send never asks it. When identity cannot be asked, the write
  fails with `500` `InternalFailure` and stores nothing, and the read fails
  the same way; both are logged. Each call is bounded by 10 seconds.
- **Standalone** (no identity endpoint) nothing is bound: a policy is stored
  and returned as it was sent, and matched by ARN.

**A send** is evaluated on the identity it sends from (above), with every
policy that identity has, an email address identity's taking precedence over
its domain's as SES documents, since the address identity is the one
evaluated when it exists, unless the send's ARN chooses another (below). A `Deny` in any policy denies, and an `Allow` in
any counts. A delegate sender in another account is allowed when its
identity policy and one of the identity's policies both allow it; within the
account the rules above apply. A send that uses a stored template is also
evaluated on the template, which has no resource-based policy, so another
account cannot send with mailbox's templates (its own, in AWS, would be in
its own account; inline content works). Its configuration set is evaluated
in the caller's account, `arn:aws:ses:<region>:<caller account>:configuration-set/<name>`,
as a delegate sender uses its own configuration sets and SES "doesn't
apply" the identity's to its mail.

**The feedback forwarding address** is evaluated the same way, on its own
identity with that identity's policies, when a send gives one:
`FeedbackForwardingEmailAddressIdentityArn` is "the ARN of the identity
that is associated with the sending authorization policy that permits you
to use the email address specified in the FeedbackForwardingEmailAddress
parameter" (SendEmail reference). So a delegate needs a grant on the
feedback address's identity as well as the sender's, and a principal of
mailbox's account needs its identity policies to allow `ses:SendEmail` on
that identity, as they must on the sender's.

**The identity ARNs a send gives** choose the identity whose policies
apply, as in SES, where the ARN is that of "the identity that is associated
with the sending authorization policy that permits you to use the email
address": `FromEmailAddressIdentityArn` and
`FeedbackForwardingEmailAddressIdentityArn` (`SendEmail` and
`SendBulkEmail`), and a raw message's `X-SES-SOURCE-ARN` and
`X-SES-FROM-ARN` headers. Each may name the address's own identity or any
identity of a domain that covers it, its domain or a parent domain, so
`identity/example.com` serves `sender@example.com` (SES's own example) even
when `sender@example.com` has an identity of its own; that identity is then
the one evaluated, with its policies. Without an ARN the address's most
granular identity is (above). The more specific identities an ARN passes
over still count for a `Deny`: an explicit `Deny` in the identity policies
on any of them, or in the sending authorization policies of any of them
that exists (evaluated with its tags), refuses the send with "... with an
explicit deny in a resource-based policy" (or the identity-based
message), while their `Allow`s do not count. So a `Deny` in
`sender@example.com`'s own policy applies to a send through
`identity/example.com`. AWS does not document whether it evaluates the
policies of an identity the ARN passes over; this is mailbox's choice, to
fail closed. The feedback address's identity is chosen and checked the same
way. An ARN is checked for every caller, the root
included, before anything is evaluated: it must be an SES identity ARN
(`BadRequestException`) of mailbox's account and region (`NotFoundException`
otherwise, as every identity mailbox holds is there and SES documents no
answer), naming an identity that covers the address (`BadRequestException`
otherwise) and exists (`NotFoundException`). `X-SES-SOURCE-ARN` is the
sender's, `X-SES-FROM-ARN` the `From` header's (both the sender's when the
request has no `FromEmailAddress`, when they must name the same identity),
and `FromEmailAddressIdentityArn` overrides both ("For Raw emails, the
FromEmailAddressIdentityArn value overrides the X-SES-SOURCE-ARN and
X-SES-FROM-ARN headers", SendEmail reference). As in SES, only the first of
a repeated header counts, and all three headers are removed.
`X-SES-RETURN-PATH-ARN` is removed and not read: a raw message's feedback
address is only the request's. `FeedbackForwardingEmailAddressIdentityArn`
needs a `FeedbackForwardingEmailAddress`.

The condition keys of a send (above) apply in these policies as in identity
policies: `ses:FromAddress`, `ses:FromDisplayName`, `ses:Recipients`,
`ses:FeedbackAddress`, `ses:ApiVersion` and the global keys. The guide lists
the SES keys for sending authorization, and gives the global keys both as
"any of the AWS-wide keys" and as a shorter list; every key mailbox supplies
is supplied to both kinds of policy.

### Gaps

- **Policies stored before 0.4 are not bound.** They keep matching by
  ARN, so a user or role deleted and created again under the same name
  inherits their grants, until each is saved again
  ([Upgrading from 0.3](#upgrading-from-03)). Standalone, every policy
  matches by ARN.
- **Service principals never match** a caller, nor do federated-user and
  `CanonicalUser` values: no Tule caller is one. A policy for a service
  principal, such as the guide's Amazon Cognito example, is stored and has
  no effect.
- **A delegate sender needs no identity ARN.** In AWS a send from another
  account without the ARN looks the identity up in the sender's own account.
  Here every identity is mailbox's account's, and a send without an ARN is
  evaluated on the most granular identity of its address.
- **No permissions boundaries, session policies, SCPs or RCPs**, as in
  tule.dev/policy; where AWS lets them limit a grant to a role ARN, the grant
  here is unlimited.
- **Domain identities are stored in lower case**, so one created as
  `Example.COM` is listed and reported as `example.com`. What SES reports
  for such a name is not documented.
- `ses:MultiRegionEndpointId` and `ses:TenantName` are not supplied: their
  features are not served. The partition is always `aws`.

## Health checks

`GET /_health` (liveness) and `GET /_ready` (readiness) answer without a
signature. They respond `200` when every service reports healthy or ready and
`503` otherwise, with a JSON object of each service's status. Readiness fails
when the database cannot be reached or its schema is not applied.

## Connecting a client

The SES API is SES v2's REST-JSON protocol under `/v2/email`, which the SDKs
already speak. Sign for the `ses` service in any region.

Go (AWS SDK v2):

```go
client := sesv2.New(sesv2.Options{
	Region:       "us-east-1",
	BaseEndpoint: aws.String("http://localhost:9040"),
	Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
})
```

JavaScript (AWS SDK v3):

```js
const client = new SESv2Client({
  region: "us-east-1",
  endpoint: "http://localhost:9040",
  credentials: { accessKeyId: "test", secretAccessKey: "test" },
});
```

Gas's `email/ses` sender works unchanged: set its `Email.Endpoint` to
`http://localhost:9040`, its region, and the configured key.

Or with `curl`, which signs requests too:

```sh
curl -fsS --aws-sigv4 aws:amz:us-east-1:ses --user test:test \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "FromEmailAddress": "sender@example.com",
    "Destination": {"ToAddresses": ["someone@example.com"]},
    "Content": {"Simple": {
      "Subject": {"Data": "Hello"},
      "Body": {"Text": {"Data": "Hi there."}}
    }}
  }' \
  http://localhost:9040/v2/email/outbound-emails
```

## Supported operations

| Operation | Notes |
|---|---|
| `SendEmail` | Simple, Raw and Template content (a stored template by `TemplateName` or `TemplateArn`, or inline `TemplateContent`). The message is stored, never sent |
| `SendBulkEmail` | Template content; one stored message per entry, and one result per entry |
| `CreateEmailIdentity` | Email addresses and domains; verified at once. A domain gets Easy DKIM tokens, or its own selector with `DkimSigningAttributes` |
| `GetEmailIdentity` | With its policies |
| `ListEmailIdentities` | Paginated; `Filter` by `IDENTITY_NAME_CONTAINS`, `IDENTITY_TYPE` and `VERIFICATION_STATUS` |
| `DeleteEmailIdentity` | Deletes its policies too |
| `CreateEmailIdentityPolicy` / `GetEmailIdentityPolicies` / `UpdateEmailIdentityPolicy` / `DeleteEmailIdentityPolicy` | Sending authorization policies, at most 20 of 4 KB per identity; see [Sending authorization](#sending-authorization) |
| `CreateEmailTemplate` / `GetEmailTemplate` / `UpdateEmailTemplate` / `DeleteEmailTemplate` | The template must be valid Handlebars |
| `ListEmailTemplates` | Paginated |
| `TestRenderEmailTemplate` | Answers the rendered MIME message |
| `GetAccount` | Production access and sending enabled, generous quotas |

Every operation is at the path and method of the SES v2 SDK model.
`ListEmailIdentities` is served both at the SDK's `POST
/v2/email/list-identities` and at `GET /v2/email/identities`, where the
botocore model the AWS CLI reads still puts it.

Requests are checked as SES checks them, with SES's errors:

- **Addresses** must parse, a display name allowed, be 7-bit ASCII, and hold
  no control character (net/mail accepts CR and LF inside an address
  comment, which would end the header line): `BadRequestException`. A message has 1 to 50 recipients across To, Cc and
  Bcc: `BadRequestException` otherwise.
- **Message size** is at most 40 MB (read as 40 MiB) as sent, attachments
  base64-encoded: `MessageRejected` beyond.
- **Headers** that Simple and Template content add: at most 15, names and
  values by the model's patterns and lengths, and none of the headers SES
  sets itself (`BCC`, `CC`, `Content-Disposition`, `Content-Type`, `Date`,
  `From`, `Message-ID`, `MIME-Version`, `Reply-To`, `Return-Path`, `Subject`,
  `To`): `BadRequestException`.
- **Attachments** by the model's lengths and enumerations, a `ContentType`
  that is `type/subtype`, no control character in `FileName`,
  `ContentDescription` or `ContentId`, and a printable ASCII `ContentId`
  (`BadRequestException`), and none of the file extensions SES refuses
  (`.exe`, `.js`, `.bat` and the rest of SES's list): `MessageRejected`.
- **Raw messages** must have a header and a body separated by a blank line,
  well-formed MIME parts, at most 500 of them, no line over 1,000 characters,
  and none of the header fields SES allows once (Subject, From, Date and the
  rest of SES's list) more than once, and no control character in the
  header but HTAB and the line endings: a CR must end a line with its LF,
  since some readers end a line on a bare CR and would see fields this
  service did not authorize the send for: `MessageRejected`.
- **Message tags**: names and values of ASCII letters, digits, `_` and `-`,
  up to 256 characters. **Resource tags** on identities and templates: at most
  50, keys of 1 to 128 and values of up to 256 characters by SES's tag rules,
  unique keys, no `aws:` prefix. Both `BadRequestException`.
- **Templates**: at most 500 KB (read as KiB) all parts together, and
  `TemplateData` of at most 262,144 characters: `BadRequestException`. At most
  20,000 templates and 10,000 identities: `LimitExceededException`.
- A name taken already is `AlreadyExistsException`; a template or identity
  that does not exist is `NotFoundException` (`404`).

Errors carry the code in the `X-Amzn-ErrorType` header and a JSON body
`{"code": "...", "message": "..."}`, which the SDKs decode into their typed
exceptions.

## How messages are built

The MessageId is in SES's shape: `0100`, the acceptance time in Unix
milliseconds as 12 hex digits, a random UUID, and `-000000`, for example
`010001a1d2cace87-87ef2327-0461-4e00-bb93-5cd7834b04bb-000000`. The message's
`Message-ID` header carries it, as
`<MessageId@email.amazonses.com>`, and its `Date` header is the acceptance
time in UTC, as SES sets both.

**Simple and Template content** are assembled the way SES assembles them:
`From`, `Reply-To`, `To`, `Cc` and `Subject` from the request (no `Bcc`
header: Bcc recipients get the message but no header names them), the
request's own headers, then `MIME-Version: 1.0`, `Date` and `Message-ID`. A
text and an HTML body go in `multipart/alternative`; inline attachments go
with the body in `multipart/related`; other attachments go with all of it in
`multipart/mixed`. Text in 7-bit ASCII is sent `7bit`, anything else
`quoted-printable`, in the request's `Charset` (UTF-8 when it names none).

Every header is 7-bit and folded to RFC 5322's lengths: lines of at most 78
characters wherever a value has spaces to break at, and never more than 998.
A subject or attachment description that is printable ASCII, including one
the client encoded already, is sent as it is, folded; one that is not, or
that has a word too long to fold, becomes RFC 2047 encoded words in its
character set. A display name that is not printable ASCII, in From, Reply-To,
To or Cc, becomes encoded words too. A file name that is not short printable
ASCII is written as RFC 2231 continuations (`filename*0*=utf-8''...`).

An attachment's content type, when the request gives none, comes from its file
name's extension. Its encoding is the request's `ContentTransferEncoding`;
without one, `7bit` when the content is 7-bit text with CRLF line endings,
and `base64` otherwise, so the recipient's copy is always the bytes attached.
An explicit `SEVEN_BIT` takes only content that is already 7-bit text in
CRLF-ended lines; anything else, a bare LF included, is refused with
`BadRequestException` rather than rewritten, since rewriting would change
the bytes the recipient gets.

**Raw content** is kept byte for byte, with what SES changes applied: its
`Message-ID` and `Date` headers are replaced by SES's own, its `Bcc` header
is removed, and the `X-SES-CONFIGURATION-SET`, `X-SES-MESSAGE-TAGS`,
`X-SES-SOURCE-ARN`, `X-SES-FROM-ARN` and `X-SES-RETURN-PATH-ARN` headers are
read and removed. The request's `FromEmailAddress`, `Destination`,
`ConfigurationSetName` and `EmailTags` take precedence over the message's
`From`, `To`/`Cc`/`Bcc` and X-SES headers; without them, the headers are used.

## Templates

Templates are Handlebars, rendered by
[raymond](https://github.com/mailgun/raymond) (`github.com/mailgun/raymond/v2`),
with what SES's renderer, Handlebars.js, does on top:

- HTML is not escaped, as SES documents.
- JSON objects keep their key order: `{{#each object}}` visits the keys in
  the order `TemplateData` gives them, so a template and its data always
  render the same.
- Numbers print as JavaScript prints them: `1.5e+21`, `1e-7`, `0` for `-0`.
- A rendering fails when it renders an attribute the data does not have, or
  has as `null` (`Attribute 'name' is not present in the rendering data.`,
  SES's text), or calls a helper that does not exist (`Missing helper:
  "eq"`, Handlebars.js's text; SES documents none).
- A rendering is bounded: it fails past 40 MiB of output, all parts
  together, or past 1,000,000 template steps, each `#each` iteration
  counting its block's steps again, so no template and data can hold the
  service.

Variables, nested paths (`{{contact.firstName}}`), `#each` (with `@index`,
`@key`, `@first`, `@last`, `this` and `../`), `#if` / `else`, `#unless`,
`#with`, a block over an attribute (`{{#list}}...{{/list}}`, as Handlebars.js
renders one), comments, `lookup` and `log` work.

**What of SES's syntax is not covered:** inline partials (`{{#* inline
"name"}}`) and partial calls (`{{> name}}`), which SES documents, and any
other decorator or partial block, are not supported by raymond: a template
using them is refused as invalid Handlebars when it is created. The second
block parameter of `#each` (`index` in `{{#each list as |item index|}}`) is
not bound and renders empty; the first is. raymond's own `equal` helper is
not Handlebars.js's, so calling it is a missing helper, as it would be on SES.

When a rendering fails, `SendEmail` and `SendBulkEmail` answer as SES does:
the message is accepted, its MessageId answered, and then it is dropped. SES
reports a Rendering Failure event, which this service has nowhere to send;
instead it records the failure, which `GET /_mailbox/rendering-failures`
lists. `TestRenderEmailTemplate` answers `BadRequestException` with the
failure's text. Template data that is not a JSON object is
`BadRequestException` everywhere.

`SendBulkEmail` renders the default template once per entry: an entry's
`ReplacementTemplateData` replaces the default data (`{}` counts as none, as
the SES developer guide describes it), its `ReplacementTags` replace the
`DefaultEmailTags` when it has any, and its `ReplacementHeaders` merge into
the template's headers, an entry header replacing a template header of the
same name, as the SDK model describes them. A template that does not exist,
or any other fault of the request itself, fails the whole call; a fault of one
entry (an invalid address, too many recipients, invalid data) fails that
entry alone with `INVALID_PARAMETER` or `MESSAGE_REJECTED`, and the other
entries are sent.

## Retrieval API

Not an AWS API. Every route is under `/_mailbox/`, signed with SigV4 for the
`ses` service exactly like the SES API (the configured key, or a key identity
issued whose policies allow `tule:Inspect`; see
[Permissions](#permissions)), and answers JSON. Errors have the SES API's shape, with
`BadRequestException` (`400`) for invalid parameters and `NotFoundException`
(`404`) for an unknown message or attachment.

```sh
alias mb='curl -fsS --aws-sigv4 aws:amz:us-east-1:ses --user test:test'
```

`GET /_mailbox/messages` lists messages, newest first, filtered by any of:

| Parameter | Matches |
|---|---|
| `from` | The From address, without regard to case |
| `to` | Any To, Cc or Bcc address, without regard to case |
| `subject` | A substring of the subject, without regard to ASCII case |
| `q` | Full text over the subject and the text body (SQLite FTS5): every word must appear; words are plain words, not FTS5 syntax |
| `since` / `until` | The time, RFC 3339, both inclusive |
| `configurationSet` | The configuration set name |
| `tag` | `name:value`, repeatable; every one must be on the message |
| `messageId` | The MessageId |

It is paginated by `limit` (1 to 100, default 20) and `cursor`, the opaque
`nextCursor` of the previous page, which is absent on the last page. A
parameter that holds a NUL character is `BadRequestException`.

```sh
mb 'http://localhost:9040/_mailbox/messages?to=someone@example.com&tag=kind:welcome&limit=10'
```

```json
{
  "items": [
    {
      "id": "010001a1d2cace87-87ef2327-0461-4e00-bb93-5cd7834b04bb-000000",
      "time": "2026-11-13T10:00:00.123Z",
      "from": "Sender <sender@example.com>",
      "to": ["someone@example.com"],
      "cc": [],
      "bcc": [],
      "subject": "Hello",
      "tags": [{"name": "kind", "value": "welcome"}],
      "configurationSet": "",
      "size": 924,
      "attachmentCount": 1
    }
  ],
  "nextCursor": "..."
}
```

`time` is RFC 3339 in UTC, to the millisecond. `from`, `to`, `cc` and `bcc`
are the addresses as sent, display names included; `to`, `cc` and `bcc` are
always arrays. `tags` is an array of `{"name", "value"}` in sent order, since
SES does not require tag names to be unique. `configurationSet` is `""` when
the message has none. `size` is the length of the stored MIME in bytes.

`GET /_mailbox/messages/{id}` returns one message: the summary fields plus
`headers`, an array of `{"name", "value"}` in message order with values decoded
from RFC 2047, `text` and `html` (`""` when the part is absent), and
`attachments`, an array of `{"name", "contentType", "size"}`, `size` being
the decoded length.

```sh
mb http://localhost:9040/_mailbox/messages/$ID
```

`GET /_mailbox/messages/{id}/raw` returns the MIME as `message/rfc822`.

```sh
mb http://localhost:9040/_mailbox/messages/$ID/raw > message.eml
```

`GET /_mailbox/messages/{id}/attachments/{index}` returns one attachment's
decoded bytes with its content type. The index is 0-based, in the order of
`attachments`, which is the order of the parts in the message: inline
attachments, which sit with the body, come before the others.

```sh
mb -o report.pdf http://localhost:9040/_mailbox/messages/$ID/attachments/0
```

`DELETE /_mailbox/messages/{id}` deletes one message, and
`DELETE /_mailbox/messages` deletes every message and every rendering
failure (identities and templates stay; they are configuration). Both answer
`204`.

```sh
mb -X DELETE http://localhost:9040/_mailbox/messages
```

`GET /_mailbox/rendering-failures` lists the templated messages that were
accepted and then dropped because their template did not render, newest
first. It filters by `messageId`, `template` (the stored template's name)
and `since` / `until`, and pages by `limit` and `cursor` as messages do. A
failed message is not a message: `GET /_mailbox/messages/{id}` answers `404`
for its MessageId.

```sh
mb 'http://localhost:9040/_mailbox/rendering-failures?template=Welcome'
```

```json
{
  "items": [
    {
      "messageId": "010001a1d2e2d903-ca230ac4-9e58-4569-a25b-1fe927ec7e4f-000000",
      "time": "2026-11-13T10:00:00.123Z",
      "source": "SendEmail",
      "template": "Welcome",
      "from": "sender@example.com",
      "to": ["someone@example.com"],
      "cc": [],
      "bcc": [],
      "tags": [],
      "configurationSet": "",
      "error": "Attribute 'name' is not present in the rendering data."
    }
  ]
}
```

`source` is `SendEmail` or `SendBulkEmail`, and `template` is `""` for inline
`TemplateContent`.

**Signing paths with curl.** curl's `--aws-sigv4` signs the path as it is
written, without the second URI encoding SigV4 gives the path of every
service but S3. A path with any character but letters, digits, `-`, `.`,
`_`, `~` and `/` therefore does not verify (`InvalidSignatureException`),
escaped or not: an email identity, whose `@` the path carries, or a template
name with a space. The retrieval API's paths are all such safe characters,
MessageIds included, and queries are not affected. For an email identity or
such a template, use an SDK or the AWS CLI, which encode the path as SigV4
requires; a domain identity (`/v2/email/identities/example.com`) works with
curl.

## Storage

One SQLite file, through gas/database and the pure-Go `modernc.org/sqlite`
driver, with the schema applied by gas/migrate. Each operation is one
transaction. A message's MIME is a blob in a table of its own beside its
metadata, at most 40 MiB, SES's size limit: in the database rather than in
files beside it, so a send and a reset each stay one transaction over one
file. Full-text search uses SQLite's FTS5, which the modernc build includes.

## Differences from AWS

- **Nothing is delivered.** Messages are stored and nothing else: no bounces,
  complaints, deliveries, opens or clicks, and no event is published anywhere:
  a templated message whose rendering fails is accepted and dropped, and the
  retrieval API's rendering failures stand in for SES's Rendering Failure
  event. The mailbox simulator addresses are ordinary addresses here.
- **Every identity is verified at once, and none is needed.** Any From address
  is accepted, whether or not an identity covers it, and there is no sandbox.
  The identity APIs work, for code that manages identities, but nothing checks
  DNS: a domain's DKIM tokens are random, its status is `SUCCESS` at once, and
  a Bring Your Own DKIM private key is required but not used. An email-address
  identity reports DKIM signing as not started.
- **Configuration sets are not modeled.** Any `ConfigurationSetName` is
  accepted and recorded with the message; none needs to exist, none has event
  destinations, and an identity's default configuration set, which is
  recorded, is not applied to messages sent without one.
- **Some request members are accepted and ignored:** `EndpointId`,
  `TenantName`, `ListManagementOptions` and `ConfigurationOverrides`.
  `FeedbackForwardingEmailAddress` is checked and recorded but receives
  nothing. The sending authorization ARNs are checked
  ([Sending authorization](#sending-authorization)).
- **The quotas are reported, not enforced.** `GetAccount` reports production
  access, sending enabled, a quota of 1,000,000 messages a day at 1,000 a
  second, and `SentLast24Hours` counting the recipients of the messages stored
  in the last 24 hours. There is no throttling, so `TooManyRequestsException`,
  `SendingPausedException` and `AccountSuspendedException` are never returned.
- **Operations outside the scope are unknown.** Configuration sets, event
  destinations, contact lists and topics, suppression lists, dedicated IPs,
  deliverability, import and export jobs, multi-region endpoints, tenants,
  tagging operations, custom verification emails and the SES v1 API answer
  `404` `UnknownOperationException`.
- **The message is mailbox's assembly, in SES's shape.** Headers SES adds in
  transit (`Return-Path`, `Received`, `Feedback-ID`, `X-SES-Outgoing`,
  `DKIM-Signature`) are not added, and the boundaries and header order are
  this service's own. The `Message-ID` header's domain is always
  `email.amazonses.com`, SES's in us-east-1, whatever region the request was
  signed for.
- **Attachment encoding.** SES documents `SEVEN_BIT` as the default
  `ContentTransferEncoding`. Without one, this service sends `7bit` only when
  the content survives it unchanged (7-bit text with CRLF line endings) and
  `base64` otherwise, so a recipient always gets the bytes attached. An
  explicit `SEVEN_BIT` on content that is not 7-bit text in CRLF-ended lines
  is refused with `BadRequestException`.
- **Text bodies are sent with CRLF line endings,** as MIME requires, so a text
  body sent with LF comes back with CRLF.
- **Text in a character set this service does not know** (in a raw message;
  Simple content with an unknown `Charset` is `BadRequestException`) is kept
  as sent in the retrieval API's `text` and `html`.
- **Error bodies** carry a `code` member beside SES's `message`, repeating the
  `X-Amzn-ErrorType` header. Error messages are modeled on SES's, which AWS
  does not document; clients are expected to match on the code.
- **Choices where AWS documents none.** Identities and templates are listed in
  creation order; a list request without `PageSize` gets pages of 10 (the
  `ListEmailTemplates` reference speaks of the "next 10"). Identity names are
  compared exactly, case included. `NextToken`s and cursors do not expire, and
  are only accepted back by the listing that issued them
  (`BadRequestException` otherwise). Templates are checked to be valid
  Handlebars when they are created or updated. An absent `TemplateData` is an
  empty object. 40 MB and 500 KB are read as MiB and KiB.
- **Signature verification is request-level,** by
  [tule.dev/sigv4](https://github.com/tulehq/sigv4). The method, path, query,
  signed headers and the body's hash are checked, along with the credential's
  access key, its service (`ses`) and a 15-minute clock skew. A request body
  larger than 64 MiB is refused with `413` `RequestEntityTooLargeException`.
  A signature must cover `host` and `x-amz-date`, and every `x-amz-*` header
  the request carries. It must carry a real SHA-256 of the body:
  `UNSIGNED-PAYLOAD` is rejected. Failures answer with the codes of the SES v2
  Common Errors page (`IncompleteSignature`, `InvalidSignatureException`,
  `UnrecognizedClientException`, `ExpiredTokenException`, all `403`), and
  `MissingAuthenticationTokenException` (`403`) for a request with no
  signature.
- **The credential's region is not checked.** It is signed, but any region
  verifies: local clients are set up for whatever region they work in.
- **Session tokens need identity.** The configured key is long-term, so a
  request signed with it and carrying `X-Amz-Security-Token` fails with
  `UnrecognizedClientException`. With identity, a role session's key verifies
  with its token; a token that is not the session's fails with
  `UnrecognizedClientException`, and an expired one with
  `ExpiredTokenException`.
- **Identity policies and sending authorization policies are enforced**, and
  only with identity; see [Permissions](#permissions) for the keys supplied
  and the gaps.
- **One process per database.** The store is one SQLite file reached through
  one connection, which serializes the server's own transactions; nothing
  coordinates two servers pointed at the same file.
- **Logs record the connection's peer address.** `X-Forwarded-For` is not
  trusted, since nothing is expected in front of this service and the header
  is unsigned.

## Upgrading from 0.3

- **identity v0.5.0 or later** (signing-key version 4) is required: the keys
  of an older identity are refused.
- **Sending authorization policies are bound to unique IDs** when they
  are stored with an identity endpoint
  ([Sending authorization](#sending-authorization)). A policy naming a user
  or role that does not exist is now refused with `BadRequestException`,
  and reads show a deleted principal's unique ID in place of its ARN. The
  policies 0.3 stored are not bound on upgrade: they keep matching by ARN,
  so a user or role deleted and created again under the same name inherits
  their grants, until each is saved again. To bind them, read each with
  `GetEmailIdentityPolicies` and write it back with
  `UpdateEmailIdentityPolicy`; a policy naming a principal that no longer
  exists is then refused, and must be corrected first.
- **`aws:PrincipalOrgID` and `aws:PrincipalOrgPaths` are supplied.** A
  condition on them that never held, or a negated one that always did,
  now follows the principal's organization; a `Deny` written as "deny
  everyone outside my organization" no longer denies the organization's
  own principals.

## Upgrading from 0.2

- **Cross-account requests are evaluated.** 0.2 refused every principal of
  another account. Now one is allowed when its identity policies and a
  resource-based policy both allow the request, which only a send can have
  (an identity's sending authorization policies); everything else is still
  denied to it, with "... because no resource-based policy allows ...".
  Another account's root user is evaluated the same way.
- **Sending authorization policies are enforced, within the account too.**
  A policy that names a user or a role session lets it send from the
  identity without an identity policy, and a `Deny` in one refuses a send
  its identity policies allow.
- **`aws:PrincipalArn` of a role session has the role's path.** A condition
  written for 0.2's path-less value, `arn:aws:iam::<account>:role/<name>`,
  no longer matches a session of a role with a path; write the ARN with the
  path. `aws:userid` and `aws:PrincipalTag/<key>` are now supplied, so a
  condition on them can now hold, and a negated one can now fail.
- **identity v0.4.0 or later** (signing-key version 3) is required: the keys
  of an older identity are refused.
- **A send's configuration set is evaluated in the caller's account**, which
  for a principal of mailbox's account is the ARN it was before.
- **The sending authorization ARNs are honored** rather than ignored: each
  chooses the identity its address is evaluated on, and one that does not
  name an existing identity covering the address is refused.
- **The feedback forwarding address's identity is evaluated.** A send with
  `FeedbackForwardingEmailAddress` now also needs `ses:SendEmail` allowed
  on that address's identity.
- A migration adds the policy table on the first start; it can be rolled
  back.

## Upgrading from 0.1

- **Permissions.** With an identity endpoint, keys identity issued are now
  held to their identity policies, and those of other accounts are refused;
  see [Permissions](#permissions).
- **Domain identity names are lower-cased.** On its first start, 0.2 runs a
  migration that lower-cases the names of the domain identities in the
  store, as lookups now compare domains without regard to case; email
  address identities keep their case. When two domain identities differ
  only by case, such as `Example.com` and `example.com`, the migration
  fails, names them and changes nothing, and mailbox does not start. Delete
  all but one of them from the database file, then the migration's dirty
  mark, and start it again:

  ```sh
  sqlite3 data/mailbox.db "DELETE FROM identities WHERE name = 'Example.com';
    DELETE FROM __gas_migrations WHERE version = '0003' AND dirty;"
  ```

## Development

```sh
make test       # unit tests
make test-e2e   # end-to-end tests: the app in-process, driven by the AWS SDK
make lint
make image      # build ghcr.io/tulehq/mailbox:dev
make smoke      # build the image, run it, and check it serves signed requests
make push VERSION=0.1.0   # build for amd64 and arm64 and push
```

The end-to-end tests include ones against real identity and accounts
services, built from their checkouts and run as processes, identity pointed
back at the app under test and at accounts for a member account. The
checkouts are mailbox's siblings, `../identity` and `../accounts`, by
default, or the directories `TULE_E2E_IDENTITY_DIR` and
`TULE_E2E_ACCOUNTS_DIR` name; CI checks out `tulehq/identity` at v0.5.0 and
`tulehq/accounts` at v0.4.0 and sets them. Without a checkout those tests
fail rather than being skipped. They include the permission tests, which give
identity's users and roles policies through the IAM SDK and check what
mailbox allows and denies.

## License

[MIT](LICENSE)
