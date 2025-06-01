const nodeCrypto = require('crypto');
const Hyperbeam = require('hyperbeam');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const { Command } = require('commander');
const goodbye = require('graceful-goodbye');
const crayon = require('tiny-crayon');
const { x25519 } = require('@noble/curves/ed25519');
const { sha256 } = require('@noble/hashes/sha256');
const { concatBytes } = require('@noble/hashes/utils');
const { pbkdf2 } = require('@noble/hashes/pbkdf2');
const { hmac } = require('@noble/hashes/hmac');
const { pipeline } = require('stream/promises');
const tar = require('tar-stream');
const pump = require('pump');

const WORDLIST = [
    'aardvark', 'absurd', 'accrue', 'acme', 'adrift', 'adult', 'afflict', 'ahead', 'aimless', 'algol', 'allow', 'alone',
    'ammo', 'ancient', 'apple', 'artist', 'assume', 'athens', 'atlas', 'aztec', 'baboon', 'backfield', 'backward', 'banjo',
    'beaming', 'bedlamp', 'beehive', 'beeswax', 'befriend', 'belfast', 'berserk', 'billiard', 'bison', 'blackjack', 'blockade', 'blowtorch',
    'bluebird', 'bombast', 'bookshelf', 'brackish', 'breadline', 'breakup', 'brickyard', 'briefcase', 'burbank', 'button', 'buzzard', 'cement',
    'chairlift', 'chatter', 'checkup', 'chisel', 'choking', 'chopper', 'christmas', 'clamshell', 'classic', 'classroom', 'cleanup', 'clockwork',
    'cobra', 'commence', 'concert', 'cowbell', 'crackdown', 'cranky', 'crowfoot', 'crucial', 'crumpled', 'crusade', 'cubic', 'dashboard',
    'deadbolt', 'deckhand', 'dogsled', 'dragnet', 'drainage', 'dreadful', 'drifter', 'dropper', 'drumbeat', 'drunken', 'dupont', 'dwelling',
    'eating', 'edict', 'egghead', 'eightball', 'endorse', 'endow', 'enlist', 'erase', 'escape', 'exceed', 'eyeglass', 'eyetooth'
];

class SimpleSPAKE2 {
    generateKeyPair() {
        const privateKey = x25519.utils.randomPrivateKey();
        const publicKey = x25519.getPublicKey(privateKey);
        return { privateKey, publicKey };
    }

    hashPassword(password) {
        const salt = nodeCrypto.randomBytes(16);
        const key = pbkdf2(sha256, password, salt, { c: 10000, dkLen: 32 });
        return { key, salt };
    }

    computeX(privateKey, passwordHash) {
        const xPrivate = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            xPrivate[i] = privateKey[i] ^ passwordHash[i];
        }
        const X = x25519.getPublicKey(xPrivate);
        return { xPrivate, X };
    }

    computeSharedSecret(xPrivate, Y) {
        return x25519.getSharedSecret(xPrivate, Y);
    }

    deriveSessionKey(isAlice, X, Y, sharedSecret) {
        const info = concatBytes(
            new TextEncoder().encode("SPAKE2 Key Derivation"),
            isAlice ? X : Y,
            isAlice ? Y : X
        );
        return hmac(sha256, sharedSecret, info);
    }
}

class HyperBeamWormhole {
    constructor() {
        this.spake2 = new SimpleSPAKE2();
    }

    static generateWormholeCode() {
        const number = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
        const word1 = WORDLIST[Math.floor(Math.random() * WORDLIST.length)];
        const word2 = WORDLIST[Math.floor(Math.random() * WORDLIST.length)];
        return `${number}-${word1}-${word2}`;
    }

    // Derive a deterministic beam key from wormhole code
    wormholeCodeToBeamKey(code) {
        // Use PBKDF2 to derive a 32-byte key from the wormhole code
        const salt = Buffer.from('hyperwormhole-beam-v1');
        const derivedKey = pbkdf2(sha256, Buffer.from(code), salt, { c: 10000, dkLen: 32 });
        return Buffer.from(derivedKey);
    }

    async send(filePath) {
        // Generate wormhole code
        const wormholeCode = HyperBeamWormhole.generateWormholeCode();
        
        // Derive beam key from wormhole code
        const beamKey = this.wormholeCodeToBeamKey(wormholeCode);
        
        // Create beam with derived key
        const beam = new Hyperbeam(beamKey);
        goodbye(() => beam.destroy());

        console.log(crayon.cyan('='.repeat(50)));
        console.log(crayon.green("Wormhole code:"), crayon.yellow(wormholeCode));
        console.log(crayon.cyan('='.repeat(50)));
        console.log('\nWaiting for receiver to connect...');

        return new Promise((resolve, reject) => {
            let connected = false;

            beam.on('error', (err) => {
                if (!connected) {
                    console.error(crayon.red('Connection error:'), err);
                    reject(err);
                }
            });

            beam.on('connected', async () => {
                connected = true;
                console.log(crayon.green('✓ Receiver connected!'));
                
                try {
                    // Perform SPAKE2 authentication using the wormhole code
                    const sessionKey = await this.performSPAKE2(beam, wormholeCode, true);
                    console.log(crayon.green('✓ Authentication successful!'));

                    // Send file metadata first
                    const stats = await fs.stat(filePath);
                    const metadata = {
                        isDirectory: stats.isDirectory(),
                        name: path.basename(filePath),
                        size: stats.size
                    };
                    
                    // Send metadata with delimiter
                    const metadataStr = JSON.stringify(metadata) + '\n';
                    beam.write(Buffer.from(metadataStr));

                    // Small delay to ensure metadata is sent first
                    await new Promise(resolve => setTimeout(resolve, 100));

                    // Stream the file content
                    if (stats.isDirectory()) {
                        console.log('\n📁 Creating archive for directory transfer...');
                        await this.streamDirectory(beam, filePath);
                    } else {
                        console.log('\n📄 Sending file...');
                        await this.streamFile(beam, filePath);
                    }

                    console.log(crayon.green('\n✓ Transfer complete!'));
                    
                    // Keep connection open briefly for receiver to finish
                    setTimeout(() => {
                        beam.end();
                        resolve();
                    }, 2000);

                } catch (error) {
                    console.error(crayon.red('Error during transfer:'), error);
                    beam.destroy();
                    reject(error);
                }
            });

            // Add timeout for connection
            setTimeout(() => {
                if (!connected) {
                    console.error(crayon.red('⏱  Timeout: No receiver connected after 5 minutes'));
                    beam.destroy();
                    reject(new Error('Connection timeout'));
                }
            }, 5 * 60 * 1000); // 5 minutes
        });
    }

    async receive(wormholeCode, outputPath = '.') {
        console.log(crayon.cyan('Connecting with wormhole code:'), crayon.yellow(wormholeCode));
        
        // Derive beam key from wormhole code
        const beamKey = this.wormholeCodeToBeamKey(wormholeCode);
        
        // Create beam with derived key
        const beam = new Hyperbeam(beamKey);
        goodbye(() => beam.destroy());

        console.log('🔍 Looking for sender...');

        return new Promise((resolve, reject) => {
            let metadata = null;
            let dataBuffer = Buffer.alloc(0);
            let metadataReceived = false;
            let authenticated = false;

            beam.on('error', (err) => {
                console.error(crayon.red('Connection error:'), err);
                reject(err);
            });

            beam.on('connected', async () => {
                console.log(crayon.green('✓ Connected to sender!'));
                
                try {
                    // Perform SPAKE2 authentication
                    const sessionKey = await this.performSPAKE2(beam, wormholeCode, false);
                    console.log(crayon.green('✓ Authentication successful!'));
                    console.log('⏳ Waiting for file data...');
                    authenticated = true;
                } catch (error) {
                    console.error(crayon.red('❌ Authentication failed:'), error);
                    beam.destroy();
                    reject(error);
                }
            });

            beam.on('data', async (chunk) => {
                if (!authenticated) return; // Wait for authentication

                try {
                    if (!metadataReceived) {
                        dataBuffer = Buffer.concat([dataBuffer, chunk]);
                        const newlineIndex = dataBuffer.indexOf('\n');
                        
                        if (newlineIndex !== -1) {
                            // Extract metadata
                            const metadataStr = dataBuffer.slice(0, newlineIndex).toString();
                            metadata = JSON.parse(metadataStr);
                            metadataReceived = true;
                            
                            console.log(`\n${metadata.isDirectory ? '📁' : '📄'} Receiving: ${crayon.cyan(metadata.name)}`);
                            console.log(`📊 Size: ${this.formatSize(metadata.size)}`);
                            
                            // Process remaining data
                            const remainingData = dataBuffer.slice(newlineIndex + 1);
                            
                            if (metadata.isDirectory) {
                                // Extract tar archive
                                await this.receiveDirectory(beam, remainingData, outputPath, metadata.name, resolve);
                            } else {
                                // Save single file
                                await this.receiveFile(beam, remainingData, outputPath, metadata.name, metadata.size, resolve);
                            }
                        }
                    }
                } catch (error) {
                    console.error(crayon.red('Error processing data:'), error);
                    reject(error);
                }
            });

            beam.on('end', () => {
                if (!metadataReceived) {
                    console.error(crayon.red('❌ Connection closed before receiving data'));
                    reject(new Error('Incomplete transfer'));
                }
            });
        });
    }

    async receiveFile(beam, initialData, outputPath, fileName, totalSize, resolve) {
        const filePath = path.join(outputPath, fileName);
        const writeStream = fsSync.createWriteStream(filePath);
        let received = initialData.length;

        // Write initial data
        writeStream.write(initialData);

        // Progress bar setup
        const updateProgress = () => {
            const percentage = Math.round((received / totalSize) * 100);
            const filled = Math.round(percentage / 2); // 50 chars width
            const bar = '█'.repeat(filled) + '░'.repeat(50 - filled);
            process.stdout.write(`\r[${bar}] ${percentage}% (${this.formatSize(received)}/${this.formatSize(totalSize)})`);
        };

        updateProgress();

        beam.on('data', (chunk) => {
            received += chunk.length;
            updateProgress();
        });

        beam.pipe(writeStream);

        writeStream.on('finish', () => {
            console.log('\n' + crayon.green(`✓ File saved to: ${filePath}`));
            resolve();
        });

        writeStream.on('error', (err) => {
            console.error(crayon.red('Write error:'), err);
            throw err;
        });
    }

    async receiveDirectory(beam, initialData, outputPath, dirName, resolve) {
        const extract = tar.extract();
        const targetDir = path.join(outputPath, dirName);
        let fileCount = 0;

        extract.on('entry', async (header, stream, next) => {
            const filePath = path.join(targetDir, header.name);
            await fs.mkdir(path.dirname(filePath), { recursive: true });
            
            if (header.type === 'file') {
                fileCount++;
                console.log(`📝 Extracting: ${header.name}`);
                const writeStream = fsSync.createWriteStream(filePath);
                stream.pipe(writeStream);
                stream.on('end', next);
            } else {
                stream.on('end', next);
                stream.resume();
            }
        });
        
        extract.on('finish', () => {
            console.log(crayon.green(`\n✓ Directory saved to: ${targetDir}`));
            console.log(crayon.green(`✓ Extracted ${fileCount} files`));
            resolve();
        });

        extract.on('error', (err) => {
            console.error(crayon.red('Extract error:'), err);
            throw err;
        });
        
        // Write initial data and pipe the rest
        if (initialData.length > 0) {
            extract.write(initialData);
        }
        beam.pipe(extract);
    }

    async performSPAKE2(beam, wormholeCode, isAlice) {
        return new Promise((resolve, reject) => {
            const { key: passwordHash, salt } = this.spake2.hashPassword(wormholeCode);
            const keyPair = this.spake2.generateKeyPair();
            const result = this.spake2.computeX(keyPair.privateKey, passwordHash);

            const timeout = setTimeout(() => {
                reject(new Error('SPAKE2 timeout'));
            }, 10000);

            if (isAlice) {
                // Alice sends salt + X
                const payload = Buffer.concat([salt, result.X]);
                beam.write(payload);

                // Wait for Bob's X
                const handleBobData = (bobData) => {
                    if (bobData.length >= 32) {
                        clearTimeout(timeout);
                        beam.removeListener('data', handleBobData);
                        
                        const bobX = bobData.slice(0, 32);
                        const sharedSecret = this.spake2.computeSharedSecret(result.xPrivate, bobX);
                        const sessionKey = this.spake2.deriveSessionKey(true, result.X, bobX, sharedSecret);
                        resolve(sessionKey);
                    }
                };
                beam.on('data', handleBobData);
            } else {
                // Bob waits for Alice's salt + X
                const handleAliceData = (aliceData) => {
                    if (aliceData.length >= 48) { // 16 bytes salt + 32 bytes X
                        clearTimeout(timeout);
                        beam.removeListener('data', handleAliceData);
                        
                        const receivedSalt = aliceData.slice(0, 16);
                        const aliceX = aliceData.slice(16, 48);
                        
                        const sharedSecret = this.spake2.computeSharedSecret(result.xPrivate, aliceX);
                        const sessionKey = this.spake2.deriveSessionKey(false, result.X, aliceX, sharedSecret);
                        
                        // Bob sends his X
                        beam.write(result.X);
                        resolve(sessionKey);
                    }
                };
                beam.on('data', handleAliceData);
            }
        });
    }

    async streamFile(beam, filePath) {
        const readStream = fsSync.createReadStream(filePath);
        let transferred = 0;
        const stats = await fs.stat(filePath);
        
        readStream.on('data', (chunk) => {
            transferred += chunk.length;
            const percentage = Math.round((transferred / stats.size) * 100);
            const filled = Math.round(percentage / 2); // 50 chars width
            const bar = '█'.repeat(filled) + '░'.repeat(50 - filled);
            process.stdout.write(`\r[${bar}] ${percentage}% (${this.formatSize(transferred)}/${this.formatSize(stats.size)})`);
        });
        
        await pipeline(readStream, beam);
        console.log(''); // New line after progress
    }

    async streamDirectory(beam, dirPath) {
        const pack = tar.pack();
        let fileCount = 0;
        let totalSize = 0;
        
        // First, calculate total size for progress
        const calculateSize = async (path) => {
            const stats = await fs.stat(path);
            if (stats.isDirectory()) {
                const entries = await fs.readdir(path);
                for (const entry of entries) {
                    await calculateSize(path + '/' + entry);
                }
            } else {
                totalSize += stats.size;
            }
        };
        
        await calculateSize(dirPath);
        console.log(`📦 Total size: ${this.formatSize(totalSize)}`);
        
        const addEntry = async (filePath, relativePath) => {
            const stats = await fs.stat(filePath);
            
            if (stats.isDirectory()) {
                const entries = await fs.readdir(filePath);
                for (const entry of entries) {
                    await addEntry(
                        path.join(filePath, entry),
                        path.join(relativePath, entry)
                    );
                }
            } else {
                fileCount++;
                console.log(`📦 Adding: ${relativePath || path.basename(filePath)}`);
                const stream = pack.entry({ 
                    name: relativePath || path.basename(filePath), 
                    size: stats.size 
                });
                const readStream = fsSync.createReadStream(filePath);
                pump(readStream, stream);
                await new Promise(resolve => stream.on('finish', resolve));
            }
        };
        
        // Start adding entries
        const packingPromise = (async () => {
            await addEntry(dirPath, '');
            pack.finalize();
            console.log(`\n📦 Archived ${fileCount} files`);
        })();
        
        // Pipe pack to beam
        const pipelinePromise = pipeline(pack, beam);
        
        // Wait for both operations
        await Promise.all([packingPromise, pipelinePromise]);
    }

    formatSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let size = Math.abs(bytes);
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        return `${size.toFixed(2)} ${units[unitIndex]}`;
    }
}

function createCLI() {
    const program = new Command();

    program
        .version('1.0.0')
        .description('HyperWormhole - Secure P2P file transfer (just like magic-wormhole!)');

    program
        .command('send <path>')
        .description('Send a file or folder')
        .action(async (filePath) => {
            const wormhole = new HyperBeamWormhole();
            try {
                // Check if file exists
                await fs.access(filePath);
                await wormhole.send(filePath);
                process.exit(0);
            } catch (error) {
                if (error.code === 'ENOENT') {
                    console.error(crayon.red(`❌ File not found: ${filePath}`));
                } else {
                    console.error(crayon.red('❌ Error:'), error.message);
                }
                process.exit(1);
            }
        });

    program
        .command('receive <code> [outputPath]')
        .alias('recv')
        .description('Receive a file or folder using wormhole code')
        .action(async (code, outputPath) => {
            const wormhole = new HyperBeamWormhole();
            try {
                await wormhole.receive(code, outputPath || process.cwd());
                process.exit(0);
            } catch (error) {
                console.error(crayon.red('❌ Error:'), error.message);
                process.exit(1);
            }
        });

    return program;
}

if (require.main === module) {
    const cli = createCLI();
    cli.parse(process.argv);
}

module.exports = HyperBeamWormhole;