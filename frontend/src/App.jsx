import { useState } from 'react';
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
  const [inputUsername, setInputUsername] = useState('mario_rossi');
  const [inputName, setInputName] = useState('Lucia Nancy');

  const addLog = (msg) => {
    setLog(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);
  };

  const fetchCredential = async () => {
    addLog("🏫 Requesting SD-JWT credential from the University Issuer...");
    try {
      const res = await fetch('/api/mock-issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: inputName, age: inputAge, role: inputRole })
      });
      const data = await res.json();
      
      wallet.storeCredential(data.sdjwt, data.disclosures, data.tslIndex);
      setHasCredential(true);
      addLog(`✅ SD-JWT stored in Wallet. Assigned to TSL index #${data.tslIndex}.`);
    } catch (e) {
      addLog("❌ Issuer error: " + e.message);
    }
  };

  const revokeCredential = async () => {
    if (!wallet.tslIndex) return;
    addLog(`🚫 Issuer is publishing revocation for TSL index #${wallet.tslIndex}...`);
    try {
      await fetch('/api/mock-revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idx: wallet.tslIndex })
      });
      addLog(`✅ Credential successfully REVOKED on the Token Status List.`);
    } catch (e) {
      addLog("❌ Revocation error: " + e.message);
    }
  };

  const registerWithRP = async () => {
    setAuthStatus('loading');
    addLog("🌐 Starting Credential Registration with the Relying Party...");
    const timings = {};
    try {
      // --- Phase 1: Selective Disclosure preparation ---
      const t0 = performance.now();
      const presentation = wallet.createPresentation(['age', 'role']);
      timings.sdJwtPresentation = (performance.now() - t0).toFixed(3);
      addLog(`🛡️ Wallet: Selective disclosure prepared in ${timings.sdJwtPresentation} ms. 'name' has been withheld.`);

      // --- Challenge generation ---
      const tChallenge0 = performance.now();
      const res1 = await fetch('/api/auth/generate-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: inputUsername })
      });
      const options = await res1.json();
      timings.challengeRoundTrip = (performance.now() - tChallenge0).toFixed(3);
      addLog(`🌐 WebAuthn challenge 'c' received from RP in ${timings.challengeRoundTrip} ms.`);

      // --- Phase 2: FIDO2 hardware signing (includes fidoac.js challenge modification) ---
      addLog("🔑 FIDO2: Awaiting biometric input (fidoac.js will inject the SD-JWT hash)...");
      const tFido0 = performance.now();
      const fidoCredential = await startRegistration(options);
      timings.fidoSigning = (performance.now() - tFido0).toFixed(3);
      addLog(`✅ Hardware signature completed on c_modified in ${timings.fidoSigning} ms.`);

      // --- Phase 3: Backend Composite Validation ---
      addLog("🌐 Sending composite payload to Backend...");
      const tVerify0 = performance.now();
      const res2 = await fetch('/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: inputUsername,
          fidoCredential,
          sdjwt: presentation.sdjwt,
          disclosures: presentation.disclosures
        })
      });
      const finalResult = await res2.json();
      timings.backendVerification = (performance.now() - tVerify0).toFixed(3);
      addLog(`⚙️ Backend composite validation (b_FIDO∧b_challenge∧b_sdjwt) completed in ${timings.backendVerification} ms.`);

      if (finalResult.success) {
        setAuthStatus('success');
        setRpAttributes({ ...finalResult.attributes, timings });
        addLog(`🎉 SUCCESS: Mediator-Free binding verified.`);
        addLog(`📊 TIMING SUMMARY: SD-JWT ${timings.sdJwtPresentation}ms | challenge ${timings.challengeRoundTrip}ms | FIDO2 signing ${timings.fidoSigning}ms | backend ${timings.backendVerification}ms`);
      } else {
        setAuthStatus('error');
        addLog(`❌ RP ERROR: ${finalResult.error}`);
      }

    } catch (e) {
      setAuthStatus('error');
      addLog("❌ Registration error: " + e.message);
    } finally {
      wallet.clearPresentation();
    }
  };

  const loginWithFIDO2 = async () => {
    setLoginStatus('loading');
    addLog("🔄 Starting Standard FIDO2 Login (no SD-JWT, no fidoac.js interception)...");
    const t0 = performance.now();
    try {
      const res1 = await fetch('/api/auth/generate-login-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: inputUsername })
      });
      const options = await res1.json();
      if (!res1.ok) { addLog("❌ Login error: " + options.error); setLoginStatus('idle'); return; }

      addLog("🔑 FIDO2: Awaiting biometric input (fidoac.js does NOT intercept this call)...");
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
        addLog(`✅ Standard FIDO2 Login successful in ${elapsed} ms total — 0 ms SD-JWT overhead.`);
        addLog(`📊 Verified attributes from DB (Issuer NOT contacted): age=${result.attributes.age}, role=${result.attributes.role}`);
      } else {
        setLoginStatus('idle');
        addLog("❌ Login failed: " + result.error);
      }
    } catch (e) {
      setLoginStatus('idle');
      addLog("❌ Login error: " + e.message);
    }
  };


  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8 font-sans">
      
      {/* Header */}
      <div className="max-w-6xl mx-auto mb-10 text-center">
        <h1 className="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400 mb-4">
          SD-JWT Mediator-Free Architecture Demonstrator
        </h1>
        <p className="text-slate-400 text-lg">
          Live demonstration of FIDO2 + Verifiable Credentials integration without a Mediator (PAwAM)
        </p>
      </div>

      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Left Panel - User Wallet */}
        <div className="bg-slate-800 rounded-3xl border border-slate-700 shadow-2xl p-6 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-blue-500"></div>
          
          <div className="flex items-center gap-3 mb-8">
            <Smartphone className="text-blue-400 w-8 h-8" />
            <h2 className="text-2xl font-bold">Local Wallet</h2>
          </div>

          {!hasCredential ? (
            <div className="text-center py-8">
              <FileBadge className="w-16 h-16 text-slate-600 mx-auto mb-4" />
              <p className="text-slate-400 mb-6">Wallet is empty. Request a credential to begin.</p>
              
              <div className="bg-slate-900 p-4 rounded-xl mb-6 text-left border border-slate-700">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">Configure identity attributes (to test different scenarios):</h4>
                <div className="flex flex-col gap-3">
                  <div>
                    <label className="text-xs text-slate-500 block mb-1">Full Name:</label>
                    <input 
                      type="text" 
                      value={inputName} 
                      onChange={(e) => setInputName(e.target.value)}
                      className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-white"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-slate-500 block mb-1">Username (FIDO2):</label>
                    <input 
                      type="text" 
                      value={inputUsername} 
                      onChange={(e) => setInputUsername(e.target.value)}
                      className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-white"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-slate-500 block mb-1">Age:</label>
                    <input 
                      type="number" 
                      value={inputAge} 
                      onChange={(e) => setInputAge(Number(e.target.value))}
                      className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-white"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-slate-500 block mb-1">Role:</label>
                    <select 
                      value={inputRole} 
                      onChange={(e) => setInputRole(e.target.value)}
                      className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-white"
                    >
                      <option value="Student">Student</option>
                      <option value="External">External</option>
                      <option value="Professor">Professor</option>
                    </select>
                  </div>
                </div>
              </div>

              <button 
                onClick={fetchCredential}
                className="bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3 px-6 rounded-xl transition-all shadow-lg hover:shadow-blue-500/30 flex items-center gap-2 mx-auto"
              >
                <ShieldCheck className="w-5 h-5" />
                Get SD-JWT from Issuer
              </button>
            </div>
          ) : (
            <div className="bg-slate-900 rounded-2xl p-6 border border-slate-700">
              <div className="flex items-center justify-between mb-6">
                <h3 className="font-semibold text-emerald-400 flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5" />
                  University Verifiable Credential
                </h3>
                <span className="text-xs font-mono bg-slate-800 px-2 py-1 rounded text-slate-400">TSL Index: #{wallet.tslIndex}</span>
              </div>
              
              <div className="space-y-3 font-mono text-sm mb-6">
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-500">Name (Withheld from RP)</span>
                  <span className="text-slate-300">{inputName}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-500">Age (Disclosed to RP)</span>
                  <span className={`font-bold ${inputAge >= 18 ? 'text-emerald-400' : 'text-amber-400'}`}>{inputAge}</span>
                </div>
                <div className="flex justify-between pb-2">
                  <span className="text-slate-500">Role (Disclosed to RP)</span>
                  <span className={`font-bold ${inputRole === 'Student' ? 'text-emerald-400' : 'text-amber-400'}`}>{inputRole}</span>
                </div>
              </div>

              <div className="flex gap-2 mt-4">
                <button 
                  onClick={revokeCredential}
                  className="flex-1 bg-red-900/30 border border-red-800 hover:bg-red-800 text-red-300 font-semibold py-2 px-4 rounded-lg transition-all text-sm"
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
                  className="flex-1 bg-slate-700 hover:bg-slate-600 text-white font-semibold py-2 px-4 rounded-lg transition-all text-sm"
                >
                  Clear Wallet
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right Panel - Relying Party */}
        <div className="bg-slate-800 rounded-3xl border border-slate-700 shadow-2xl p-6 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-emerald-500"></div>
          
          <div className="flex items-center gap-3 mb-8">
            <Globe className="text-emerald-400 w-8 h-8" />
            <h2 className="text-2xl font-bold">Relying Party (Web Portal)</h2>
          </div>

          <div className="text-center py-6">
            <h3 className="text-xl mb-2">Restricted Access Area</h3>
            <p className="text-sm text-slate-400 mb-8">
              Requires attributes <strong>age</strong> and <strong>role</strong> via FIDO2.
            </p>

            {authStatus === 'idle' && (
              <button 
                onClick={registerWithRP}
                disabled={!hasCredential}
                className={`font-semibold py-3 px-6 rounded-xl transition-all shadow-lg flex items-center gap-2 mx-auto ${
                  hasCredential 
                  ? "bg-emerald-600 hover:bg-emerald-500 text-white hover:shadow-emerald-500/30" 
                  : "bg-slate-700 text-slate-500 cursor-not-allowed"
                }`}
              >
                <Fingerprint className="w-5 h-5" />
                Authenticate with FIDO2 &amp; SD-JWT
              </button>
            )}

            {authStatus === 'loading' && (
              <div className="animate-pulse text-emerald-400 flex items-center justify-center gap-2">
                <Key className="w-5 h-5 animate-spin" /> Cryptographic processing...
              </div>
            )}

            {authStatus === 'success' && rpAttributes && (
              <div className="bg-emerald-900/30 border border-emerald-500/50 rounded-2xl p-6">
                <h3 className="text-emerald-400 font-bold mb-4 text-lg">✅ Access Granted</h3>
                <p className="text-sm text-slate-300 mb-4">The equation b_FIDO ∧ b_challenge ∧ b_sdjwt is satisfied.</p>
                <div className="text-left bg-slate-900 p-4 rounded-xl font-mono text-sm text-slate-300 mb-4">
                  <p className="text-emerald-400 mb-2">// Attributes revealed via Selective Disclosure</p>
                  <p>"age": {rpAttributes.age}</p>
                  <p>"role": "{rpAttributes.role}"</p>
                </div>
                {rpAttributes.timings && (
                  <div className="text-left bg-slate-950 p-4 rounded-xl font-mono text-xs text-slate-400 border border-slate-700 mb-4">
                    <p className="text-amber-400 mb-2">// 📊 Performance Measurements (ms)</p>
                    <p>SD-JWT Presentation (client): <span className="text-white">{rpAttributes.timings.sdJwtPresentation} ms</span></p>
                    <p>Challenge round-trip (network): <span className="text-white">{rpAttributes.timings.challengeRoundTrip} ms</span></p>
                    <p>FIDO2 hw signing + fidoac.js: <span className="text-white">{rpAttributes.timings.fidoSigning} ms</span></p>
                    <p>Backend validation (b_FIDO∧b_chal∧b_sdjwt): <span className="text-white">{rpAttributes.timings.backendVerification} ms</span></p>
                  </div>
                )}

                {/* Standard FIDO2 Login — subsequent session */}
                <div className="border-t border-emerald-700/50 pt-4 mt-2">
                  <p className="text-xs text-slate-400 mb-3">Credential Registration complete. Simulate a subsequent login with standard FIDO2 — no SD-JWT, no fidoac.js:</p>
                  {loginStatus === 'idle' && (
                    <button
                      onClick={loginWithFIDO2}
                      className="bg-blue-700 hover:bg-blue-600 text-white font-semibold py-2 px-5 rounded-xl transition-all flex items-center gap-2 mx-auto text-sm"
                    >
                      <LogIn className="w-4 h-4" />
                      Standard FIDO2 Login (0 ms overhead)
                    </button>
                  )}
                  {loginStatus === 'loading' && (
                    <div className="animate-pulse text-blue-400 flex items-center justify-center gap-2 text-sm">
                      <Key className="w-4 h-4 animate-spin" /> Standard FIDO2 in progress...
                    </div>
                  )}
                  {loginStatus === 'success' && (
                    <div className="bg-blue-900/30 border border-blue-500/50 rounded-xl p-4 text-left font-mono text-xs">
                      <p className="text-blue-300 font-bold mb-2">✅ Standard FIDO2 Login — {loginTimings} ms total</p>
                      <p className="text-slate-400">SD-JWT overhead: <span className="text-white font-bold">0 ms</span></p>
                      <p className="text-slate-400">Issuer contacted: <span className="text-white font-bold">NO</span></p>
                      <p className="text-slate-400">fidoac.js active: <span className="text-white font-bold">NO</span></p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {authStatus === 'error' && (
              <div className="bg-red-900/30 border border-red-500/50 rounded-2xl p-6">
                <h3 className="text-red-400 font-bold mb-4 text-lg">❌ Access Denied</h3>
                <p className="text-sm text-slate-300">Check the execution log below for details (e.g. Age or Role does not satisfy the RP policy).</p>
                <button 
                  onClick={() => setAuthStatus('idle')}
                  className="mt-4 bg-red-800 hover:bg-red-700 text-white font-semibold py-2 px-4 rounded-lg transition-all text-sm"
                >
                  Try Again
                </button>
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Terminal Log */}
      <div className="max-w-6xl mx-auto mt-8">
        <div className="bg-black rounded-2xl p-4 border border-slate-700 shadow-xl h-64 overflow-y-auto font-mono text-sm">
          <div className="text-slate-500 mb-2"># Execution log</div>
          {log.map((l, i) => (
            <div key={i} className={`${l.includes('❌') ? 'text-red-400' : l.includes('✅') || l.includes('🎉') ? 'text-emerald-400' : 'text-slate-300'} mb-1`}>
              {l}
            </div>
          ))}
          {log.length === 0 && <div className="text-slate-600 italic">Waiting for events...</div>}
        </div>
      </div>

    </div>
  )
}

export default App
