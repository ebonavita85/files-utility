document.getElementById('fileInput').addEventListener('change', handleFileSelect);

// Funzione principale che si attiva al cambio del file
function handleFileSelect(event) {
    const file = event.target.files[0];

    // Reset dei risultati
    document.getElementById('fileName').textContent = 'Nessun file selezionato';
    document.getElementById('mimeType').textContent = 'N/A';
    document.getElementById('hashMd5').textContent = 'Calcolo...';
    document.getElementById('hashSha256').textContent = 'Calcolo...';
    
    if (!file) {
        return;
    }

    // 1. Identificazione del Tipo
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('mimeType').textContent = file.type || 'Sconosciuto (tipo non fornito dal browser)';

    // 2. Calcolo degli Hash
    calculateHashes(file);
}

// Funzione per convertire ArrayBuffer in stringa esadecimale (necessario per SubtleCrypto)
function bufferToHex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => (('00' + x.toString(16)).slice(-2))).join('');
}

// Funzione che esegue il calcolo degli hash
async function calculateHashes(file) {
    const reader = new FileReader();

    reader.onload = async function(e) {
        const buffer = e.target.result; // Contenuto del file come ArrayBuffer
        
        // --- 2a. Calcolo SHA-256 (API Nativa Web Crypto) ---
        try {
            const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
            const sha256 = bufferToHex(hashBuffer);
            document.getElementById('hashSha256').textContent = sha256;
        } catch (error) {
            document.getElementById('hashSha256').textContent = `Errore: ${error.message}`;
        }
        
        // --- 2b. Calcolo MD5 (Libreria CryptoJS) ---
        try {
            // CryptoJS può lavorare con ArrayBuffer. Lo convertiamo in un WordArray.
            const wordArray = CryptoJS.lib.WordArray.create(buffer);
            const md5Hash = CryptoJS.MD5(wordArray).toString(CryptoJS.enc.Hex);
            document.getElementById('hashMd5').textContent = md5Hash;
        } catch (error) {
            document.getElementById('hashMd5').textContent = `Errore: ${error.message}`;
        }
    };

    // Iniziamo la lettura del file come ArrayBuffer
    reader.readAsArrayBuffer(file);
}
