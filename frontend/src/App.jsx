import { useState } from 'react';
import { startRegistration } from '@simplewebauthn/browser';
import { initFidoAC } from './fidoac.js';
import { LocalWallet } from './Wallet.js';
import { Smartphone, Globe, ShieldCheck, Key, Fingerprint, FileBadge } from 'lucide-react';

// Initialize the monkey-patch
initFidoAC();
const wallet = new LocalWallet();

function App() {
  const [log, setLog] = useState([]);
  const [hasCredential, setHasCredential] = useState(false);
  const [authStatus, setAuthStatus] = useState('idle'); // idle, loading, success, error
  const [rpAttributes, setRpAttributes] = useState(null);
  const [inputAge, setInputAge] = useState(24);
  const [inputRole, setInputRole] = useState('Student');
  const [inputUsername, setInputUsername] = useState('mario_rossi');
  const [inputName, setInputName] = useState('Lucia Nancy');

  const addLog = (msg) => {
    setLog(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);
  };

  const fetchCredential = async () => {
    addLog("🏫 Richiesta in corso verso l'Issuer Universitario...");
    try {
      const res = await fetch('/api/mock-issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: inputName, age: inputAge, role: inputRole })
      });
      const data = await res.json();
      
      wallet.storeCredential(data.sdjwt, data.disclosures, data.tslIndex);
      setHasCredential(true);
      addLog(`✅ SD-JWT salvata. Assegnata alla cella TSL #${data.tslIndex}.`);
    } catch (e) {
      addLog("❌ Errore Issuer: " + e.message);
    }
  };

  const revokeCredential = async () => {
    if (!wallet.tslIndex) return;
    addLog(`🚫 L'Issuer sta pubblicando la revoca della cella TSL #${wallet.tslIndex}...`);
    try {
      await fetch('/api/mock-revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idx: wallet.tslIndex })
      });
      addLog(`✅ Credenziale REVOCATA con successo sul Token Status List.`);
    } catch (e) {
      addLog("❌ Errore Revoca: " + e.message);
    }
  };

  const registerWithRP = async () => {
    setAuthStatus('loading');
    addLog("🌐 Avvio Credential Registration verso il RP...");
    const timings = {};
    try {
      // --- Phase 1: Selective Disclosure preparation ---
      const t0 = performance.now();
      const presentation = wallet.createPresentation(['age', 'role']);
      timings.sdJwtPresentation = (performance.now() - t0).toFixed(3);
      addLog(`🛡️ Wallet: Preparata selective disclosure in ${timings.sdJwtPresentation} ms. 'name' è stato nascosto.`);

      // --- Challenge generation ---
      const tChallenge0 = performance.now();
      const res1 = await fetch('/api/auth/generate-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: inputUsername })
      });
      const options = await res1.json();
      timings.challengeRoundTrip = (performance.now() - tChallenge0).toFixed(3);
      addLog(`🌐 Ricevuto WebAuthn challenge 'c' dal RP in ${timings.challengeRoundTrip} ms.`);

      // --- Phase 2: FIDO2 hardware signing (includes fidoac.js challenge modification) ---
      addLog("🔑 FIDO2: In attesa di input biometrico (fidoac.js inietterà l'hash)...");
      const tFido0 = performance.now();
      const fidoCredential = await startRegistration(options);
      timings.fidoSigning = (performance.now() - tFido0).toFixed(3);
      addLog(`✅ Firma hardware completata su c_modified in ${timings.fidoSigning} ms.`);

      // --- Phase 3: Backend Composite Validation ---
      addLog("🌐 Invio payload composito al Backend...");
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
      addLog(`⚙️ Validazione composita backend completata in ${timings.backendVerification} ms.`);

      if (finalResult.success) {
        setAuthStatus('success');
        setRpAttributes({ ...finalResult.attributes, timings });
        addLog(`🎉 SUCCESSO: Mediator-Free binding verificato.`);
        addLog(`📊 RIEPILOGO TEMPI: SD-JWT pres. ${timings.sdJwtPresentation}ms | challenge ${timings.challengeRoundTrip}ms | firma FIDO2 ${timings.fidoSigning}ms | verifica backend ${timings.backendVerification}ms`);
      } else {
        setAuthStatus('error');
        addLog(`❌ ERRORE RP: ${finalResult.error}`);
      }

    } catch (e) {
      setAuthStatus('error');
      addLog("❌ Errore durante la registrazione: " + e.message);
    } finally {
      wallet.clearPresentation();
    }
  };


  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8 font-sans">
      
      {/* Header */}
      <div className="max-w-6xl mx-auto mb-10 text-center">
        <h1 className="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400 mb-4">
          Dimostratore Architettura SD-JWT Mediator-Free
        </h1>
        <p className="text-slate-400 text-lg">
          Dimostrazione pratica dell'integrazione FIDO2 + Verifiable Credentials senza mediatore (PAwAM)
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
              <p className="text-slate-400 mb-6">Il wallet è vuoto. Richiedi una credenziale per iniziare.</p>
              
              <div className="bg-slate-900 p-4 rounded-xl mb-6 text-left border border-slate-700">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">Scegli i tuoi dati (per testare i vari casi):</h4>
                <div className="flex flex-col gap-3">
                  <div>
                    <label className="text-xs text-slate-500 block mb-1">Nome e Cognome:</label>
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
                    <label className="text-xs text-slate-500 block mb-1">Età:</label>
                    <input 
                      type="number" 
                      value={inputAge} 
                      onChange={(e) => setInputAge(Number(e.target.value))}
                      className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-white"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-slate-500 block mb-1">Ruolo:</label>
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
                Ottieni SD-JWT dall'Issuer
              </button>
            </div>
          ) : (
            <div className="bg-slate-900 rounded-2xl p-6 border border-slate-700">
              <div className="flex items-center justify-between mb-6">
                <h3 className="font-semibold text-emerald-400 flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5" />
                  Credenziale Universitaria
                </h3>
                <span className="text-xs font-mono bg-slate-800 px-2 py-1 rounded text-slate-400">TSL Index: #{wallet.tslIndex}</span>
              </div>
              
              <div className="space-y-3 font-mono text-sm mb-6">
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-500">Nome (Nascosto al RP)</span>
                  <span className="text-slate-300">{inputName}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-500">Età (Selezionato per RP)</span>
                  <span className={`font-bold ${inputAge >= 18 ? 'text-emerald-400' : 'text-amber-400'}`}>{inputAge}</span>
                </div>
                <div className="flex justify-between pb-2">
                  <span className="text-slate-500">Ruolo (Selezionato per RP)</span>
                  <span className={`font-bold ${inputRole === 'Student' ? 'text-emerald-400' : 'text-amber-400'}`}>{inputRole}</span>
                </div>
              </div>

              <div className="flex gap-2 mt-4">
                <button 
                  onClick={revokeCredential}
                  className="flex-1 bg-red-900/30 border border-red-800 hover:bg-red-800 text-red-300 font-semibold py-2 px-4 rounded-lg transition-all text-sm"
                >
                  Simula Revoca
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
                  Svuota Wallet
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
            <h2 className="text-2xl font-bold">Relying Party (Sito Web)</h2>
          </div>

          <div className="text-center py-6">
            <h3 className="text-xl mb-2">Area ad Accesso Ristretto</h3>
            <p className="text-sm text-slate-400 mb-8">
              Richiede l'attributo <strong>age</strong> e <strong>role</strong> tramite FIDO2.
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
                Autenticati con FIDO2 & SD-JWT
              </button>
            )}

            {authStatus === 'loading' && (
              <div className="animate-pulse text-emerald-400 flex items-center justify-center gap-2">
                <Key className="w-5 h-5 animate-spin" /> Elaborazione crittografica...
              </div>
            )}

            {authStatus === 'success' && rpAttributes && (
              <div className="bg-emerald-900/30 border border-emerald-500/50 rounded-2xl p-6">
                <h3 className="text-emerald-400 font-bold mb-4 text-lg">✅ Accesso Garantito</h3>
                <p className="text-sm text-slate-300 mb-4">L'equazione b_FIDO ∧ b_challenge ∧ b_sdjwt è soddisfatta.</p>
                <div className="text-left bg-slate-900 p-4 rounded-xl font-mono text-sm text-slate-300 mb-4">
                  <p className="text-emerald-400 mb-2">// Dati rivelati in Data Minimization</p>
                  <p>"age": {rpAttributes.age}</p>
                  <p>"role": "{rpAttributes.role}"</p>
                </div>
                {rpAttributes.timings && (
                  <div className="text-left bg-slate-950 p-4 rounded-xl font-mono text-xs text-slate-400 border border-slate-700">
                    <p className="text-amber-400 mb-2">// 📊 Misurazioni di Performance (ms)</p>
                    <p>SD-JWT Presentation (client): <span className="text-white">{rpAttributes.timings.sdJwtPresentation} ms</span></p>
                    <p>Challenge round-trip (rete): <span className="text-white">{rpAttributes.timings.challengeRoundTrip} ms</span></p>
                    <p>FIDO2 hw signing + fidoac.js: <span className="text-white">{rpAttributes.timings.fidoSigning} ms</span></p>
                    <p>Backend validation (b_FIDO∧b_chal∧b_sdjwt): <span className="text-white">{rpAttributes.timings.backendVerification} ms</span></p>
                  </div>
                )}
              </div>
            )}


            {authStatus === 'error' && (
              <div className="bg-red-900/30 border border-red-500/50 rounded-2xl p-6">
                <h3 className="text-red-400 font-bold mb-4 text-lg">❌ Accesso Negato</h3>
                <p className="text-sm text-slate-300">Controlla i log nel terminale per i dettagli (es. Età o Ruolo non conformi alla policy).</p>
                <button 
                  onClick={() => setAuthStatus('idle')}
                  className="mt-4 bg-red-800 hover:bg-red-700 text-white font-semibold py-2 px-4 rounded-lg transition-all text-sm"
                >
                  Riprova
                </button>
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Terminal Log */}
      <div className="max-w-6xl mx-auto mt-8">
        <div className="bg-black rounded-2xl p-4 border border-slate-700 shadow-xl h-64 overflow-y-auto font-mono text-sm">
          <div className="text-slate-500 mb-2"># Terminale di esecuzione locale</div>
          {log.map((l, i) => (
            <div key={i} className={`${l.includes('❌') ? 'text-red-400' : l.includes('✅') || l.includes('🎉') ? 'text-emerald-400' : 'text-slate-300'} mb-1`}>
              {l}
            </div>
          ))}
          {log.length === 0 && <div className="text-slate-600 italic">In attesa di eventi...</div>}
        </div>
      </div>

    </div>
  )
}

export default App
