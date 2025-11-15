document.getElementById('fileInput').addEventListener('change', handleFileSelect);

// Funzione di utilità per formattare la dimensione in modo leggibile (es. 1.2 MB)
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Funzione principale che si attiva al cambio del file
function handleFileSelect(event) {
    const file = event.target.files[0];

    // Reset dei risultati
    document.getElementById('fileName').textContent = 'Nessun file selezionato';
    document.getElementById('mimeType').textContent = 'N/A';
    document.getElementById('fileSize').textContent = 'N/A'; // Reset Dimensione
    document.getElementById('fileExtension').textContent = 'N/A'; // Reset Estensione
    document.getElementById('lastModified').textContent = 'N/A';
    document.getElementById('hashMd5').textContent = 'Calcolo...';
    document.getElementById('hashSha256').textContent = 'Calcolo...';
    document.getElementById('hashSha1').textContent = 'Calcolo...';
    document.getElementById('hashSha384').textContent = 'Calcolo...';
    document.getElementById('hashSha512').textContent = 'Calcolo...';
    document.getElementById('hashCrc32').textContent = 'Calcolo...';
    
    if (!file) {
        return;
    }

    // 1. Identificazione del Tipo, Dimensione ed Estensione
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('mimeType').textContent = file.type || 'Sconosciuto';

    // Dimensione del file (file.size è in byte)
    document.getElementById('fileSize').textContent = formatBytes(file.size);

    // Estensione del file
    // Cerca l'ultimo punto (.) nel nome del file
    const lastDotIndex = file.name.lastIndexOf('.');
    let extension = 'Nessuna estensione';
    if (lastDotIndex !== -1 && lastDotIndex < file.name.length - 1) {
        extension = file.name.substring(lastDotIndex + 1).toUpperCase();
    }
    document.getElementById('fileExtension').textContent = extension;

    if (file.lastModifiedDate) {
        // Usa toLocaleString() per formattare la data e l'ora in base alle impostazioni locali
        const formattedDate = file.lastModifiedDate.toLocaleString();
        document.getElementById('lastModified').textContent = formattedDate;
    } else {
        document.getElementById('lastModified').textContent = 'Non disponibile';
    }

    // 2. Calcolo degli Hash
    calculateHashes(file);
}


// Funzione per convertire ArrayBuffer in stringa esadecimale (necessario per SubtleCrypto)
function bufferToHex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => (('00' + x.toString(16)).slice(-2))).join('');
}

async function calculateHashes(file) {
    const reader = new FileReader();

    reader.onload = async function(e) {
        const buffer = e.target.result; // Contenuto del file come ArrayBuffer
        const byteArray = new Uint8Array(buffer); // Versione usata per CRC32

        // --- 1. Calcoli SHA (API Nativa Web Crypto) ---
        
        // SHA-1
        getShaHash('SHA-1', buffer, 'hashSha1');
        
        // SHA-256 (esistente)
        getShaHash('SHA-256', buffer, 'hashSha256');
        
        // SHA-384
        getShaHash('SHA-384', buffer, 'hashSha384');
        
        // SHA-512
        getShaHash('SHA-512', buffer, 'hashSha512');

        
        // --- 2. Calcolo MD5 (Libreria CryptoJS) ---
        try {
            const wordArray = CryptoJS.lib.WordArray.create(buffer);
            const md5Hash = CryptoJS.MD5(wordArray).toString(CryptoJS.enc.Hex);
            document.getElementById('hashMd5').textContent = md5Hash;
        } catch (error) {
            document.getElementById('hashMd5').textContent = `Errore MD5: ${error.message}`;
        }
        
        // --- 3. Calcolo CRC32 (Libreria crc-32) ---
        try {
            // La libreria CRC32 lavora meglio con un array di byte
            const crc32Value = CRC32.buf(byteArray);
            
            // Il risultato è un numero intero. Convertiamolo in esadecimale a 8 cifre.
            const crc32Hex = (crc32Value >>> 0).toString(16).toUpperCase().padStart(8, '0');
            document.getElementById('hashCrc32').textContent = crc32Hex;
        } catch (error) {
            document.getElementById('hashCrc32').textContent = `Errore CRC32: ${error.message}`;
        }

    };

    // Iniziamo la lettura del file come ArrayBuffer
    reader.readAsArrayBuffer(file);
}


// Funzione che esegue il calcolo degli hash
async function _calculateHashes(file) {
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
