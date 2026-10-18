// The Security Testing Authorization and Confidentiality Agreement that invited security testers sign on
// the site (typed full name + checkbox) before they enter the test environment or create API keys.
// Draft wording, not reviewed by a lawyer. Changing the text means changing TESTER_TERMS_VERSION, which asks
// every tester to sign again.

export const TESTER_TERMS_VERSION = '2026-10-16-tester-v2';

export const TESTER_AGREEMENT_HTML = `
<p>This agreement is between <b>Daniel Oden</b> ("Owner"), owner of MonkeyITM-VM, and you ("Tester"), the person
signing below with the GitHub account you are signed in with. Version ${TESTER_TERMS_VERSION}.</p>

<h2>1. Permission to test</h2>
<p>The Owner authorizes you to perform security testing of MonkeyITM-VM, limited to:</p>
<ul>
<li>this website and its API (<code>monkeyitm-vm.o87enterprises.workers.dev</code>), using only accounts the Owner invited;</li>
<li>runners the Owner starts for you during agreed test windows;</li>
<li>any copy of the source code the Owner gives you, run on machines you control;</li>
<li>model servers and other systems you own and control.</li>
</ul>
<p>For you and for this testing only, this permission overrides the parts of the Terms of Use that forbid probing,
reverse engineering or attacking the service. Every other part of the Terms of Use still applies.</p>

<h2>2. What you will not do</h2>
<ul>
<li>Test or attack any system or account belonging to GitHub, Vercel, Cloudflare, NVIDIA or any other third party.</li>
<li>Run flooding, volumetric or denial-of-service attacks. Describe such a weakness instead of exploiting it.</li>
<li>Phish or socially engineer anyone.</li>
<li>Access, keep or use data or credentials that do not belong to your own test accounts. If you reach any, stop,
do not use them, and tell the Owner promptly.</li>
<li>Use any finding for any purpose other than this testing, or share your access with anyone.</li>
</ul>

<h2>3. Confidentiality</h2>
<p>"Confidential Information" means the source code, documentation, designs, system internals, credentials and
findings that the Owner shares with you or that you learn while testing. You will:</p>
<ul>
<li>keep Confidential Information private and use it only for this testing;</li>
<li>not share it with anyone without the Owner's written permission;</li>
<li>not disclose any finding publicly until the Owner agrees in writing, or until 90 days after you report it to
the Owner, whichever comes first;</li>
<li>delete or return the source code and documentation when testing ends, if the Owner asks.</li>
</ul>
<p>Information that is already public, or that you already knew independently, is not confidential. These duties
last two years after your testing ends.</p>

<h2>4. Ownership and reports</h2>
<p>The Owner owns MonkeyITM-VM and everything in it. The Owner may use your reports freely to fix and improve the
system and to describe its security, without naming you unless you agree.</p>

<h2>5. Good faith, ending</h2>
<p>The service is provided as is, with no warranty. Both sides act in good faith. The Owner will not pursue claims
against you for testing done within this agreement. Either side may end your testing at any time by email; the
Owner may also revoke your invitation and keys.</p>

<h2>6. Signing</h2>
<p>Typing your full name and pressing "Sign and continue" signs this agreement electronically. We record your
GitHub login, email, the name you typed, this version and the time. That signature record is kept for as long
as this agreement's duties last, even if you delete your account.</p>`;
