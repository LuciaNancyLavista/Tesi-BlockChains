import { useState, useEffect } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import { initFidoAC } from './fidoac.js';
import { LocalWallet } from './Wallet.js';
import { Smartphone, Globe, ShieldCheck, Key, Fingerprint, FileBadge, LogIn } from 'lucide-react';

// Initialize the monkey-patch
initFidoAC();
const wallet = new LocalWallet();

function App() {
  const [log, setLog] = useState([]);
  const [hasCredential, setHasCredential] = useState(false);
  const [authStatus, setAuthStatus] = useState('idle'); // idle, loading, success, error
  const [loginStatus, setLoginStatus] = useState('idle'); // idle, loading, success
  const [rpAttributes, setRpAttributes] = useState(null);
  const [loginTimings, setLoginTimings] = useState(null);
  const [inputAge, setInputAge] = useState(24);
  const [inputRole, setInputRole] = useState('Student');
  const [inputUsername, setInputUsername] = useState('lucia');
  const [inputName, setInputName] = useState('Lucia Nancy');

  useEffect(() => {
    wallet.loadFromStorage().then(loaded => {
      if (loaded) {
        setHasCredential(true);
        addLog("[STATE] Wallet state restored from local storage.");
      }
    });
  }, []);

  const addLog = (msg) => {
    setLog(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);
  };

  const fetchCredential = async () => {
    addLog("[REQ] Generating Holder keypair (ECDSA P-256) for SD-JWT Key Binding...");
    try {
      // Step 1: generate the Wallet holder keypair BEFORE contacting the Issuer.
      // holderPublicKeyJwk will be embedded in the SD-JWT cnf claim by the Issuer.
      const holderPublicKeyJwk = await wallet.generateHolderKeypair();
      addLog("[CRYPTO] Holder keypair generated. Public key ready for cnf claim.");

      addLog("[NET] Requesting SD-JWT credential from the University Issuer (with cnf key binding)...");
      const res = await fetch('/api/mock-issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: inputName,
          age: inputAge,
          role: inputRole,
          holderPublicKey: holderPublicKeyJwk   // → Issuer will embed this as cnf.jwk
        })
      });
      const data = await res.json();
      
      wallet.storeCredential(data.sdjwt, data.disclosures, data.tslIndex);
      setHasCredential(true);
      addLog(`[OK] SD-JWT stored in Wallet (cnf.jwk bound to holder key). TSL index #${data.tslIndex}.`);
    } catch (e) {
      addLog("[ERROR] Issuer error: " + e.message);
    }
  };


  const revokeCredential = async () => {
    if (!wallet.tslIndex) return;
    addLog(`[REQ] Issuer is publishing revocation for TSL index #${wallet.tslIndex}...`);
    try {
      await fetch('/api/mock-revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idx: wallet.tslIndex })
      });
      addLog(`[OK] Credential successfully REVOKED on the Token Status List.`);
    } catch (e) {
      addLog("[ERROR] Revocation error: " + e.message);
    }
  };

  const registerWithRP = async () => {
    setAuthStatus('loading');
    addLog("[NET] Starting Credential Registration with the Relying Party (KB-JWT binding)...");
    const timings = {};
    try {
      // ── Phase 1: Selective Disclosure preparation ────────────────────────────
      const t0 = performance.now();
      const presentation = wallet.createPresentation(['age', 'role']);
      timings.sdJwtPresentation = (performance.now() - t0).toFixed(3);
      addLog(`[WALLET] Selective disclosure prepared in ${timings.sdJwtPresentation} ms. 'name' withheld.`);

      // ── Challenge generation ─────────────────────────────────────────────────
      const tChallenge0 = performance.now();
      const res1 = await fetch('/api/auth/generate-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: inputUsername })
      });
      const options = await res1.json();
      const originalChallenge = options.challenge;  // Save raw challenge before fidoac.js modifies it
      timings.challengeRoundTrip = (performance.now() - tChallenge0).toFixed(3);
      addLog(`[NET] WebAuthn challenge 'c' received from RP in ${timings.challengeRoundTrip} ms.`);

      // ── Phase 2a: KB-JWT generation (NEW) ───────────────────────────────────
      const rpOrigin = window.location.origin;
      const tKbJwt0 = performance.now();
      const kbJwt = await wallet.signKbJwt(originalChallenge, presentation.sdjwt, rpOrigin);
      timings.kbJwtGeneration = (performance.now() - tKbJwt0).toFixed(3);
      addLog(`[CRYPTO] KB-JWT generated and signed with holderPrivKey in ${timings.kbJwtGeneration} ms.`);
      addLog(`[CRYPTO] -> KB-JWT proves: credential ownership & this session & this SD-JWT.`);

      // ── Phase 2b: Expose KB-JWT to fidoac.js for c_modified injection ────────
      // fidoac.js will compute: c_modified = c || SHA-256(KB-JWT)
      window.__fidoac_kbjwt = kbJwt;

      // ── Phase 2c: FIDO2 hardware signing (includes fidoac.js modification) ───
      addLog("[FIDO2] Awaiting biometric input (fidoac.js will inject SHA-256(KB-JWT) into challenge)...");
      const tFido0 = performance.now();
      const fidoCredential = await startRegistration(options);
      timings.fidoSigning = (performance.now() - tFido0).toFixed(3);
      addLog(`[OK] Hardware signature on c_modified = c || SHA-256(KB-JWT) in ${timings.fidoSigning} ms.`);
      addLog(`[CRYPTO] -> Cryptographic chain: FIDO2_sig -> KB-JWT -> SD-JWT_pres`);

      // Cleanup: clear KB-JWT from global state
      window.__fidoac_kbjwt = null;

      // ── Phase 3: Backend Composite Validation ────────────────────────────────
      addLog("[NET] Sending composite payload to Backend for b_FIDO & b_challenge & b_sdjwt & b_cnf...");
      const tVerify0 = performance.now();
      const res2 = await fetch('/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: inputUsername,
          fidoCredential,
          sdjwt: presentation.sdjwt,
          disclosures: presentation.disclosures,
          kbJwt         // Backend uses this to verify b_cnf: KB-JWT signed with cnf.jwk key
        })
      });
      const finalResult = await res2.json();
      timings.backendVerification = (performance.now() - tVerify0).toFixed(3);
      addLog(`[BACKEND] Composite validation completed in ${timings.backendVerification} ms.`);

      if (finalResult.success) {
        setAuthStatus('success');
        setRpAttributes({ ...finalResult.attributes, timings });
        addLog(`[SUCCESS] Mediator-Free binding verified (b_FIDO & b_challenge & b_sdjwt & b_cnf).`);
        addLog(`[TIMING] SD-JWT ${timings.sdJwtPresentation}ms | KB-JWT ${timings.kbJwtGeneration}ms | challenge ${timings.challengeRoundTrip}ms | FIDO2 ${timings.fidoSigning}ms | backend ${timings.backendVerification}ms`);
      } else {
        setAuthStatus('error');
        addLog(`[FAIL] RP ERROR: ${finalResult.error}`);
      }

    } catch (e) {
      setAuthStatus('error');
      addLog("[ERROR] Registration error: " + e.message);
    } finally {
      wallet.clearPresentation();
      window.__fidoac_kbjwt = null;  // Safety cleanup
    }
  };


  const loginWithFIDO2 = async () => {
    setLoginStatus('loading');
    addLog("[NET] Starting Standard FIDO2 Login (no SD-JWT, no fidoac.js interception)...");
    const t0 = performance.now();
    try {
      const res1 = await fetch('/api/auth/generate-login-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: inputUsername })
      });
      const options = await res1.json();
      if (!res1.ok) { addLog("[ERROR] Login error: " + options.error); setLoginStatus('idle'); return; }

      addLog("[FIDO2] Awaiting biometric input (fidoac.js does NOT intercept this call)...");
      const fidoAssertion = await startAuthentication(options);

      const res2 = await fetch('/api/auth/verify-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: inputUsername, fidoAssertion })
      });
      const result = await res2.json();
      const elapsed = (performance.now() - t0).toFixed(0);

      if (result.success) {
        setLoginStatus('success');
        setLoginTimings(elapsed);
        addLog(`[OK] Standard FIDO2 Login successful in ${elapsed} ms total — 0 ms SD-JWT overhead.`);
        addLog(`[INFO] Verified attributes from DB (Issuer NOT contacted): age=${result.attributes.age}, role=${result.attributes.role}`);
      } else {
        setLoginStatus('idle');
        addLog("[FAIL] Login failed: " + result.error);
      }
    } catch (e) {
      setLoginStatus('idle');
      addLog("[ERROR] Login error: " + e.message);
    }
  };


  return (
    <div className="min-h-screen bg-[#eef1f6] text-[#0f172a] p-8 md:p-12 font-sans">
      
      {/* Header */}
      <header className="max-w-6xl mx-auto mb-10 pb-8 border-b border-[#d6dceb] text-center">
        <h1 className="text-6xl font-extrabold text-[#1e3a8a] mb-3 tracking-tight">TrustChain</h1>
      </header>

      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        
        {/* Left Panel - User Wallet */}
        <section className="bg-white rounded-2xl border-2 border-[#c7d2fe] p-8 shadow-[0_2px_10px_rgba(29,78,216,0.06)]">
          <h2 className="text-[26px] font-bold text-[#1e3a8a] mb-2">User Wallet Client</h2>
          <p className="text-[16px] text-[#64748b] mb-6">Local software holding the SD-JWT credential and the holder key.</p>
          <hr className="border-t border-[#e2e8f0] mb-6" />

          {!hasCredential ? (
            <div className="py-2">
              <p className="text-[#64748b] mb-5 font-medium text-[16px]">Wallet is empty. Configure identity attributes and request a credential.</p>
              
              <div className="bg-[#f8fafc] p-6 rounded-xl mb-6 border border-[#e2e8f0]">
                <div className="flex flex-col gap-5">
                  <div>
                    <label className="text-[15px] text-[#64748b] font-bold block mb-2">Full Name</label>
                    <input 
                      type="text" 
                      value={inputName} 
                      onChange={(e) => setInputName(e.target.value)}
                      className="w-full bg-white border border-[#cbd5e1] rounded-lg px-4 py-3 text-[17px] font-bold text-[#0f172a] focus:ring-2 focus:ring-[#1d4ed8] focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="text-[15px] text-[#64748b] font-bold block mb-2">Username (FIDO2)</label>
                    <input 
                      type="text" 
                      value={inputUsername} 
                      onChange={(e) => setInputUsername(e.target.value)}
                      className="w-full bg-white border border-[#cbd5e1] rounded-lg px-4 py-3 text-[17px] font-bold text-[#0f172a] focus:ring-2 focus:ring-[#1d4ed8] focus:outline-none"
                    />
                  </div>
                  <div className="flex gap-5">
                    <div className="flex-1">
                      <label className="text-[15px] text-[#64748b] font-bold block mb-2">Age</label>
                      <input 
                        type="number" 
                        value={inputAge} 
                        onChange={(e) => setInputAge(Number(e.target.value))}
                        className="w-full bg-white border border-[#cbd5e1] rounded-lg px-4 py-3 text-[17px] font-bold text-[#0f172a] focus:ring-2 focus:ring-[#1d4ed8] focus:outline-none"
                      />
                    </div>
                    <div className="flex-1">
                      <label className="text-[15px] text-[#64748b] font-bold block mb-2">Role</label>
                      <select 
                        value={inputRole} 
                        onChange={(e) => setInputRole(e.target.value)}
                        className="w-full bg-white border border-[#cbd5e1] rounded-lg px-4 py-3 text-[17px] font-bold text-[#0f172a] focus:ring-2 focus:ring-[#1d4ed8] focus:outline-none"
                      >
                        <option value="Student">Student</option>
                        <option value="External">External</option>
                        <option value="Professor">Professor</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>

              <button 
                onClick={fetchCredential}
                className="w-full bg-[#1d4ed8] hover:bg-[#1e40af] text-white font-bold py-5 px-6 rounded-xl text-[18px] shadow-[0_4px_14px_rgba(37,99,235,0.35)] transition-all"
              >
                Request SD-JWT from Issuer
              </button>
            </div>
          ) : (
            <div>
              <div className="bg-[#f8fafc] border border-[#e2e8f0] rounded-xl p-6 mb-6">
                <div className="flex items-center justify-between mb-5">
                  <h3 className="font-bold text-[18px] m-0">University Verifiable Credential</h3>
                  <span className="font-mono text-[14px] font-bold bg-[#e0e7ff] text-[#1e3a8a] px-3 py-1 rounded-full">TSL Index #{wallet.tslIndex}</span>
                </div>
                
                <div>
                  <div className="flex justify-between items-baseline py-3 border-b border-[#eef2f7]">
                    <span className="text-[15px] text-[#64748b]">Name (withheld from RP)</span>
                    <span className="font-mono text-[17px] font-medium text-[#94a3b8]">{inputName}</span>
                  </div>
                  <div className="flex justify-between items-baseline py-3 border-b border-[#eef2f7]">
                    <span className="text-[15px] text-[#64748b]">Age (disclosed to RP)</span>
                    <span className="font-mono text-[17px] font-bold text-[#0f7a3d]">{inputAge}</span>
                  </div>
                  <div className="flex justify-between items-baseline py-3">
                    <span className="text-[15px] text-[#64748b]">Role (disclosed to RP)</span>
                    <span className="font-mono text-[17px] font-bold text-[#0f7a3d]">{inputRole}</span>
                  </div>
                </div>
              </div>

              <div className="flex gap-4">
                <button 
                  onClick={revokeCredential}
                  className="flex-1 bg-[#b91c1c] hover:bg-[#991b1b] text-white font-bold py-4 px-4 rounded-lg text-[16px] transition-colors"
                >
                  Simulate Revocation
                </button>
                <button 
                  onClick={() => {
                    setHasCredential(false);
                    setAuthStatus('idle');
                    setRpAttributes(null);
                    wallet.clearPresentation();
                    wallet.tslIndex = null;
                  }}
                  className="flex-1 bg-[#eef2f7] hover:bg-[#e2e8f0] border border-[#d6dceb] text-[#0f172a] font-bold py-4 px-4 rounded-lg text-[16px] transition-colors"
                >
                  Clear Wallet
                </button>
              </div>
            </div>
          )}
        </section>

        {/* Right Panel - Relying Party */}
        <section className="bg-[#0b1220] rounded-2xl border-2 border-[#2b3a5c] p-8 text-[#f1f5f9]">
          <h2 className="text-[26px] font-bold mb-2">Relying Party Portal</h2>
          <p className="text-[16px] text-[#9aa8c2] mb-6">Restricted-access university service enforcing an SD-JWT policy.</p>
          <hr className="border-t border-[#2b3a5c] mb-6" />

          {/* ----- PHASES 1-3: REGISTRATION ----- */}
          <div className="mb-8">
            {authStatus === 'idle' && (
              <div>
                <p className="text-[15px] text-[#9aa8c2] mb-6">
                  Requires attributes <b className="text-[#f1f5f9]">age</b> and <b className="text-[#f1f5f9]">role</b>, bound to a FIDO2 hardware signature.
                </p>
                <button 
                  onClick={registerWithRP}
                  disabled={!hasCredential}
                  className={`w-full font-bold py-5 px-6 rounded-xl text-[18px] transition-all ${
                    hasCredential 
                    ? "bg-[#1d4ed8] hover:bg-[#1e40af] text-white shadow-[0_4px_14px_rgba(37,99,235,0.35)]" 
                    : "bg-[#1e293b] text-[#475569] cursor-not-allowed"
                  }`}
                >
                  Credential Registration (Phases 1-3)
                </button>
              </div>
            )}

            {authStatus === 'loading' && (
              <div className="text-[#7ee787] font-bold flex flex-col items-center justify-center gap-3 py-10">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#7ee787]"></div>
                Cryptographic processing in progress...
              </div>
            )}

            {authStatus === 'success' && rpAttributes && (
              <div className="bg-[#0d1526] border border-[#2ea043] rounded-xl p-6 shadow-sm">
                <div className="flex justify-between items-start mb-4">
                  <h3 className="text-[#3fb950] font-bold text-xl m-0">✅ Registration Complete: Access Granted</h3>
                  <button onClick={() => setAuthStatus('idle')} className="text-[#9aa8c2] hover:text-white text-[13px] underline">Reset</button>
                </div>
                
                <div className="bg-[#0b1220] p-5 rounded-lg font-mono text-[15px] text-[#c9d1d9] mb-6 border border-[#30363d]">
                  <p className="text-[#7ee787] mb-3 font-bold">// Disclosed Attributes</p>
                  <p>"age": <span className="font-bold text-white">{rpAttributes.age}</span></p>
                  <p>"role": "<span className="font-bold text-white">{rpAttributes.role}</span>"</p>
                </div>
                
                {rpAttributes.timings && (
                  <div className="bg-[#0b1220] p-5 rounded-lg font-mono text-[14px] text-[#8b949e] border border-[#30363d] m-0">
                    <p className="text-[#a5d6ff] font-bold mb-4">// Phase Performance (ms)</p>
                    <p>Phase 1 (Wallet prep):<span className="text-[#c9d1d9] float-right">{rpAttributes.timings.sdJwtPresentation + rpAttributes.timings.kbJwtGeneration}</span></p>
                    <p>Phase 2 (Interceptor):<span className="text-[#c9d1d9] float-right">{rpAttributes.timings.fidoSigning}</span></p>
                    <p>Phase 3 (Backend):<span className="text-[#c9d1d9] float-right">{rpAttributes.timings.backendVerification}</span></p>
                    <p>Network RTT:<span className="text-[#c9d1d9] float-right">{rpAttributes.timings.challengeRoundTrip}</span></p>
                  </div>
                )}
              </div>
            )}

            {authStatus === 'error' && (
              <div className="bg-[#241318] border border-[#f85149] rounded-xl p-6 shadow-sm">
                <h3 className="text-[#ff7b72] font-bold mb-4 text-xl">❌ Access Denied</h3>
                <p className="text-[15px] text-[#c9d1d9] mb-6">Policy requirements not met. Check execution log below.</p>
                <button 
                  onClick={() => setAuthStatus('idle')}
                  className="w-full bg-[#b91c1c] hover:bg-[#991b1b] text-white font-bold py-4 rounded-lg transition-colors text-[16px]"
                >
                  Dismiss
                </button>
              </div>
            )}
          </div>

          <hr className="border-t border-[#2b3a5c] mb-8" />
          
          {/* ----- SUBSEQUENT LOGIN ----- */}
          <div className="bg-[#111827] p-6 rounded-xl border border-[#374151]">
            <h4 className="text-white font-bold text-[19px] mb-2">Subsequent Logins</h4>
            <p className="text-[15px] text-[#9ca3af] mb-6">
              If you have already completed the Credential Registration, you can log in directly without the SD-JWT overhead.
            </p>
            {loginStatus === 'idle' && (
              <button
                onClick={loginWithFIDO2}
                disabled={!hasCredential}
                className={`w-full font-bold py-4 rounded-xl transition-colors text-[16px] shadow-lg ${
                  hasCredential
                  ? "bg-[#3b82f6] hover:bg-[#2563eb] border border-[#2563eb] text-white"
                  : "bg-[#1e293b] text-[#475569] cursor-not-allowed"
                }`}
              >
                Simulate Standard FIDO2 Login
              </button>
            )}
            {loginStatus === 'loading' && (
              <div className="text-[#79c0ff] font-bold text-center py-4 text-[15px]">
                FIDO2 Auth in progress...
              </div>
            )}
            {loginStatus === 'success' && (
              <div className="bg-[#0d1526] border border-[#388bfd] rounded-lg p-5 font-mono text-[14px] mt-2 text-[#8b949e]">
                <div className="flex justify-between items-start mb-3">
                  <p className="text-[#79c0ff] font-bold text-[15px] m-0">✅ Standard FIDO2 — {loginTimings} ms</p>
                  <button onClick={() => setLoginStatus('idle')} className="text-[#8b949e] hover:text-white text-[12px] underline">Reset</button>
                </div>
                <p>SD-JWT overhead: <span className="text-white">0 ms</span></p>
                <p>Interceptor active: <span className="text-white">NO</span></p>
              </div>
            )}
            {loginStatus === 'error' && (
              <div className="bg-[#241318] border border-[#f85149] rounded-lg p-4 font-mono text-[14px] mt-2 text-[#ff7b72] flex justify-between items-center">
                <span>❌ Login failed. Are you registered?</span>
                <button onClick={() => setLoginStatus('idle')} className="text-[#ff7b72] underline">Reset</button>
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Terminal Log */}
      <div className="max-w-6xl mx-auto bg-[#0d1117] border border-[#30363d] rounded-2xl p-6 md:p-8 shadow-xl">
        <div className="font-mono text-[#8b949e] text-[15px] tracking-[0.03em] mb-6 uppercase font-bold"># System Execution Log</div>
        <div className="h-64 overflow-y-auto pr-2">
          {log.map((l, i) => {
            // Helper to style log tags like [NET], [OK]
            let colorClass = "text-[#c9d1d9]";
            if (l.includes('[ERROR]') || l.includes('[FAIL]')) colorClass = "text-[#ff7b72] font-bold";
            else if (l.includes('[OK]') || l.includes('[SUCCESS]')) colorClass = "text-[#3fb950] font-bold";
            else if (l.includes('[NET]')) colorClass = "text-[#a5d6ff] font-bold";
            else if (l.includes('[BACKEND]')) colorClass = "text-[#79c0ff] font-bold";
            else if (l.includes('[CRYPTO]')) colorClass = "text-[#d2a8ff] font-bold";
            else if (l.includes('[FIDO2]')) colorClass = "text-[#7ee787] font-bold";
            
            return (
              <div key={i} className={`font-mono text-[17px] leading-[1.8] pl-4 border-l-4 ${i === 0 ? 'border-[#58a6ff] bg-[#58a6ff14] rounded-r-md py-1' : 'border-transparent py-1'} mb-1`}>
                <span className={colorClass}>{l}</span>
              </div>
            );
          })}
          {log.length === 0 && <div className="font-mono text-[#6e7681] text-[16px] italic">Waiting for execution events...</div>}
        </div>
      </div>

    </div>
  )
}

export default App
