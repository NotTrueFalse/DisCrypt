// ==UserScript==
// @name         DisCrypt
// @version      1.0
// @description  auto encrypt / decrypt your messages
// @author       NotTrueFalse
// @match        https://discord.com/*
// @match        https://*.discord.com/*
// @run-at       document-end
// @grant        none
// @require      https://cdn.jsdelivr.net/npm/tweetnacl
// ==/UserScript==

/*
Mechanism:

Start by hijacking the sendMessage function for auto encryption
Wait for localstorage to be removed to restore it
Wait for the library to load
retreive keypair / peer / config data
initialisation of everything.
*/


(function () {
    'use strict';

    function get_url_channel_id() {
        const match = window.location.pathname.match(/\/channels\/(@me|\d+)\/(\d+)/);
        if (match) { return match[2]; }
    }

    function encodeUTF8(utf8_string) {
        return new TextEncoder().encode(utf8_string);
    }

    function decodeUTF8(uint8Array) {
        return new TextDecoder().decode(uint8Array);
    }

    function encodeBase64(uint8Array) {
        let binary = '';
        for (let i = 0; i < uint8Array.length; i++) {
            binary += String.fromCharCode(uint8Array[i]);
        }
        return btoa(binary);
    }

    function decodeBase64(base64String) {
        const binary = atob(base64String);
        const uint8Array = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            uint8Array[i] = binary.charCodeAt(i);
        }
        return uint8Array;
    }

    async function sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function isValidEd25519PubKey(key) {
        try {
            const decoded = decodeBase64(key);
            return decoded.length === 32;
        } catch {
            return false;
        }
    }


    // Crypto functions using nacl (X25519 ECDH + XSalsa20-Poly1305)
    async function encryptMessage(message, recipientPubKeyB64) {
        try {
            if (!my_keypair) {
                throw new Error('No keypair available');
            }
            const recipientPubKey = decodeBase64(recipientPubKeyB64);
            const messageUint8 = encodeUTF8(message);
            const nonce = nacl.randomBytes(nacl.box.nonceLength);
            // Encrypt using ECDH: only recipient with their private key can decrypt
            const encrypted = nacl.box(
                messageUint8,
                nonce,
                recipientPubKey,
                my_keypair.secretKey
            );
            if (!encrypted) {
                throw new Error('Encryption failed');
            }

            return {
                ciphertext: encodeBase64(encrypted),
                nonce: encodeBase64(nonce),
                senderPubKey: encodeBase64(my_keypair.publicKey)
            };
        } catch (error) {
            console.error('Encryption error:', error);
            return null;
        }
    }

    async function decryptMessage(ciphertext, nonce, otherPartyPubKeyB64) {
        try {
            if (!my_keypair) {
                throw new Error('No keypair available');
            }

            // Convert from base64
            const encryptedData = decodeBase64(ciphertext);
            const nonceData = decodeBase64(nonce);
            const otherPartyPubKey = decodeBase64(otherPartyPubKeyB64);

            const decrypted = nacl.box.open(
                encryptedData,
                nonceData,
                otherPartyPubKey,
                my_keypair.secretKey
            );

            if (!decrypted) {
                throw new Error('Decryption failed - invalid key or corrupted data');
            }

            return decodeUTF8(decrypted);
        } catch (error) {
            console.error('Decryption error:', error);
            return null;
        }
    }


    async function _raw_text_decryption(encryptedText) {
        try {
            // Parse format: [prefix][nonce]:[ciphertext]:[senderPubKey]:[recipientPubKey]
            // Remove the prefix character properly (it's multi-byte UTF-8)
            const withoutPrefix = encryptedText.substring(prefix.length);
            const parts = withoutPrefix.split(':');
            if (parts.length !== 4) {
                console.log('Invalid encrypted message format, expected 4 parts, got:', parts.length, parts);
                return;
            }

            if (!my_keypair) {
                return -1;
            }

            const [nonce, ciphertext, senderPubKey, recipientPubKey] = parts;

            const myPubKeyB64 = encodeBase64(my_keypair.publicKey);
            const isSender = senderPubKey === myPubKeyB64;
            const isRecipient = recipientPubKey === myPubKeyB64;

            let decrypted;
            try {
                if (isSender) {
                    decrypted = await decryptMessage(ciphertext, nonce, recipientPubKey);
                } else if (isRecipient) {
                    decrypted = await decryptMessage(ciphertext, nonce, senderPubKey);
                } else {
                    decrypted = -1;
                }
                return { decrypted, isSender };
            } catch (e) {
                console.log("failed to decrypt:", e);
            }
        } catch (e) {
            console.error('Error decrypting raw text message:', error);
        }
    }

    function extractMessageData(messageElement) {
        try {
            // Extract message ID from element id (format: chat-messages-123456789-123456789)
            let messageId = messageElement.id?.replace('chat-messages-', '');
            messageId = messageId.split("-")[messageId.split("-").length - 1];

            const contentElement = messageElement.querySelector(':not([class^="repliedTextContent"])[id^="message-content-"] span');
            const ReplyElem = messageElement.querySelector(`#message-reply-context-${messageId}`);
            if (!(contentElement && messageId)) return;

            const messageContent = contentElement?.textContent;

            if (messageContent?.startsWith(prefix)) {
                handleEncryptedMessage(messageContent, contentElement);
            }

            if (ReplyElem) {
                const ReplyContentElement = ReplyElem.querySelector("[id^='message-content-'] span");
                const ReplyContent = ReplyContentElement?.textContent;
                if (ReplyContent?.startsWith(prefix)) {
                    handleEncryptedMessage(ReplyContent, ReplyContentElement);
                }
            }

            console.log('New message detected:\n' +
                ('Message ID:' + messageId + "\n") +
                ('Content:' + messageContent)
            );
            return { message: { elem: contentElement, id: messageId } };
        } catch (error) {
            console.error('Error extracting message data:', error);
        }
        return null;
    }

    async function handleEncryptedMessage(encryptedText, contentElement) {
        let decrypted_data = await _raw_text_decryption(encryptedText);
        if (decrypted_data == -1) {
            contentElement.textContent = '[Encrypted message - not for you]';
            contentElement.style.color = '#99aab5';
            return;
        }
        if (decrypted_data) {
            contentElement.textContent = decrypted_data.decrypted;
            contentElement.style.color = decrypted_data.isSender ? '#5865F2' : '#43b581';
        } else {
            contentElement.textContent = '[Encrypted message - cannot decrypt]';
            contentElement.style.color = '#faa61a';
        }
    }

    function wait_for_webpack(callback) {
        if (!window.webpackChunkdiscord_app) {
            return setTimeout(wait_for_webpack, 100, callback);
        }
        callback();
    }
    window.base_functions = {};

    let selected_peer_userId;

    let prefix = "⌭";

    wait_for_webpack(() => {
        console.log("webpack loaded");
        let found = false;
        function try_hijack() {
            if (found) return;
            console.log("trying to hijack functions...");
            window.webpackChunkdiscord_app.push([[Symbol()], {}, o => {
                for (let k of Object.keys(o.c)) {
                    let module = o.c[k];
                    if (found) return;
                    try {
                        if (!module.exports || module.exports === window) continue;
                        for (let oo in module.exports) {
                            if (found) return;
                            let multiple_functions = module.exports[oo];
                            for (let function_name of ["sendMessage", "editMessage", "patchMessageAttachments", "startEditMessageRecord", "endEditMessage"]) {// "getSendMessageOptionsForReply","receiveMessage"]) {
                                if (function_name in multiple_functions && multiple_functions[function_name][Symbol.toStringTag] != "IntlMessagesProxy") {
                                    window.base_functions[function_name] = multiple_functions[function_name];
                                    // console.log(function_name, multiple_functions[function_name]);
                                    switch (function_name) {
                                        case "sendMessage":
                                            multiple_functions[function_name] = async (...args) => {
                                                let channel_id = args[0];
                                                let message = args[1];
                                                if (channel_id in known_peer) {
                                                    selected_peer_userId = channel_id;
                                                }
                                                // console.log("discrypt:", message);
                                                if (!("id" in message) && selected_peer_userId) {
                                                    //!("id in message) => before pending state, we can modify content here
                                                    const encrypted = await encryptMessage(message.content, known_peer[selected_peer_userId]);
                                                    if (!encrypted) {
                                                        alert('Message encryption failed !');
                                                        return;
                                                    }
                                                    // Format: [prefix][nonce]:[ciphertext]:[senderPubKey]:[known_peer[selected_peer_userId]]
                                                    const encryptedMessage = `${prefix}${encrypted.nonce}:${encrypted.ciphertext}:${encrypted.senderPubKey}:${known_peer[selected_peer_userId]}`;
                                                    message["content"] = encryptedMessage;
                                                    args[1] = message;
                                                }
                                                return window.base_functions[function_name](...args);
                                            };
                                            break;
                                        case "startEditMessageRecord":
                                            multiple_functions[function_name] = async (...args) => {
                                                let channel_id = args[0];
                                                let message = args[1];
                                                if (channel_id in known_peer) {
                                                    selected_peer_userId = channel_id;
                                                }
                                                if (selected_peer_userId && message.content.startsWith(prefix)) {
                                                    const decrypted_data = await _raw_text_decryption(message.content);
                                                    if (!decrypted_data || decrypted_data == -1) {
                                                        alert('Message encryption failed !');
                                                        return;
                                                    }
                                                    message["content"] = decrypted_data.decrypted;
                                                    args[1] = message;
                                                }
                                                return window.base_functions[function_name](...args);
                                            }
                                            break;
                                        case "editMessage":
                                            multiple_functions[function_name] = async (...args) => {
                                                let channel_id = args[0];
                                                // let message_id = args[1];
                                                let message = args[2];
                                                if (channel_id in known_peer) {
                                                    selected_peer_userId = channel_id;
                                                }
                                                if (selected_peer_userId) {
                                                    const encrypted = await encryptMessage(message.content, known_peer[selected_peer_userId]);
                                                    if (!encrypted) {
                                                        alert('Message encryption failed !');
                                                        return;
                                                    }
                                                    const encryptedMessage = `${prefix}${encrypted.nonce}:${encrypted.ciphertext}:${encrypted.senderPubKey}:${known_peer[selected_peer_userId]}`;
                                                    message["content"] = encryptedMessage;
                                                    args[2] = message;
                                                }
                                                return window.base_functions[function_name](...args);
                                            }
                                            break;
                                        case "endEditMessage":
                                            multiple_functions[function_name] = async (...args) => {
                                                window.base_functions[function_name](...args);
                                                // let focusMessage do its thing
                                                //so we can immeditaly edit the message afterward.
                                                let channel_id = args[0];
                                                let edit_payload = args[1];
                                                if (channel_id in known_peer) {
                                                    selected_peer_userId = channel_id;
                                                }
                                                //we get the message element then decrypt it
                                                if (selected_peer_userId && edit_payload?.body && edit_payload?.status < 300) {
                                                    let edited_message = document.getElementById(`chat-messages-${edit_payload.body.channel_id}-${edit_payload.body.id}`);
                                                    const waitForEncryptedVersion = () => {
                                                        const messageContent = edited_message.querySelector(':not([class^="repliedTextContent"])[id^="message-content-"] span').textContent || '';
                                                        if (messageContent.startsWith(prefix)) {
                                                            return extractMessageData(edited_message);
                                                        } 
                                                        setTimeout(waitForEncryptedVersion, 10);
                                                    };
                                                    waitForEncryptedVersion();
                                                }
                                            }
                                            break;
                                        default:
                                            if (multiple_functions[function_name].constructor.name == 'AsyncFunction') {
                                                multiple_functions[function_name] = async (...args) => {
                                                    console.log(`discrypt  async (${function_name}): ${JSON.stringify(args)}`);
                                                    return await window.base_functions[function_name](...args);
                                                }
                                            } else {
                                                multiple_functions[function_name] = (...args) => {
                                                    console.log(`discrypt (${function_name}): ${JSON.stringify(args)}`);
                                                    return window.base_functions[function_name](...args);
                                                }
                                            }
                                            break;
                                    }
                                    found = 1;
                                }
                            }
                        }
                    } catch { }
                }

            }]);
            window.webpackChunkdiscord_app.pop();
            if (!found) {
                setTimeout(try_hijack, 100);
            } else {
                console.log("hijacked function send / receive message");
            }
        }
        try_hijack();
    });


    function restore_localstorage() {
        if (window.localStorage) {
            setTimeout(restore_localstorage, 100);
            return console.log("waiting to restore localstorage...");
        }
        function getLocalStoragePropertyDescriptor() {
            const iframe = document.createElement('iframe');
            document.head.append(iframe);
            const pd = Object.getOwnPropertyDescriptor(iframe.contentWindow, 'localStorage');
            iframe.remove();
            return pd;
        }
        Object.defineProperty(window, 'localStorage', getLocalStoragePropertyDescriptor());
    }

    restore_localstorage();

    function save_peers(peers) {
        localStorage.setItem("discrypt-peers", JSON.stringify(peers));
    }

    function save_keypair(keypair) {
        localStorage.setItem("discrypt-keypair", JSON.stringify(keypair));
    }

    function get_keypair() {
        let keypair_string = localStorage.getItem("discrypt-keypair");
        if (!keypair_string) return null;
        try {
            const parsed = JSON.parse(keypair_string);
            return {
                publicKey: decodeBase64(parsed.publicKey),
                secretKey: decodeBase64(parsed.secretKey)
            };
        } catch (e) {
            console.log("Something went wrong when loading keypair:", e);
            return null;
        }
    }


    function get_peers() {
        let peers_string = localStorage.getItem("discrypt-peers");
        if (!peers_string) { save_peers({}); return {}; }
        try {
            return JSON.parse(peers_string);
        } catch (e) {
            console.log("Something went wrong when loading peers:", e);
            return -1;
        }
    }

    let known_peer = get_peers();
    if (known_peer == -1) { return; }

    let my_keypair = get_keypair();

    console.log("Loaded peers:", known_peer, "and keypair:", my_keypair);


    function waitForLibraries(callback) {
        if (nacl) {
            callback();
        } else {
            setTimeout(() => waitForLibraries(callback), 100);
        }
    }

    waitForLibraries(initDiscrypt);

    function initDiscrypt() {

        function createPeerSelectorUI() {
            // Create a floating peer selector that appears near the message input
            const selector = document.createElement('div');
            selector.id = 'discrypt-peer-selector';
            selector.style.cssText = `
                position: fixed;
                bottom: 80px;
                right: 20px;
                z-index: 9999;
                background: #2f3136;
                border: 2px solid #5865F2;
                border-radius: 8px;
                padding: 10px;
                color: white;
                min-width: 200px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
                display: none;
            `;

            selector.innerHTML = `
                <div style="font-weight: bold; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                    🔐 Encrypt for:
                    <button id="discrypt-close-selector" style="background: transparent; border: none; color: #ed4245; cursor: pointer; font-size: 16px; padding: 0;">✕</button>
                </div>
                <select id="discrypt-peer-select" style="width: 100%; padding: 6px; background: #40444b; border: 1px solid #202225; color: white; border-radius: 4px; cursor: pointer;">
                    <option value="">-- No encryption --</option>
                </select>
                <div style="margin-top: 8px; font-size: 11px; color: #99aab5;" id="discrypt-selector-hint">
                    Select a peer to encrypt messages
                </div>
            `;

            document.body.appendChild(selector);

            // Event listeners
            document.getElementById('discrypt-close-selector').addEventListener('click', () => {
                selector.style.display = 'none';
            });

            const selectElement = document.getElementById('discrypt-peer-select');
            selectElement.addEventListener('change', (e) => {
                const userId = e.target.value;
                if (userId) {
                    selected_peer_userId = userId;
                    document.getElementById('discrypt-selector-hint').textContent = `✓ Encrypting for user ${userId}`;
                    document.getElementById('discrypt-selector-hint').style.color = '#43b581';
                } else {
                    selected_peer_userId = null;
                    document.getElementById('discrypt-selector-hint').textContent = 'Select a peer to encrypt messages';
                    document.getElementById('discrypt-selector-hint').style.color = '#99aab5';
                }
            });

            return selector;
        }

        function updatePeerSelector(channelId) {
            const selector = document.getElementById('discrypt-peer-selector');
            const selectElement = document.getElementById('discrypt-peer-select');

            if (!selector || !selectElement) return;
            const isDM = Object.keys(known_peer).includes(channelId);

            if (isDM) {
                selected_peer_userId = channelId;
                selector.style.display = 'none';
            } else {
                selected_peer_userId = null;
                selectElement.innerHTML = '<option value="">-- No encryption --</option>';

                Object.entries(known_peer).forEach(([userId, pubKey]) => {
                    const option = document.createElement('option');
                    option.value = userId;
                    option.textContent = `User ${userId}`;
                    selectElement.appendChild(option);
                });

                if (selected_peer_userId && known_peer[selected_peer_userId]) {
                    selectElement.value = selected_peer_userId;
                    document.getElementById('discrypt-selector-hint').textContent = `✓ Encrypting for user ${selected_peer_userId}`;
                    document.getElementById('discrypt-selector-hint').style.color = '#43b581';
                } else {
                    selected_peer_userId = null;
                }

                selector.style.display = 'block';
            }
        }

        function createGUI(callback) {
            const oldButton = document.querySelector('#discrypt-settings-button');
            if (oldButton) oldButton.remove();

            const findSidebarContainer = () => {
                return document.querySelector('[class*="scroller_"][class*="none_"]') ||
                    document.querySelector('[class*="scrollerBase_"]');
            };

            const sidebarContainer = findSidebarContainer();

            if (!sidebarContainer) {
                console.log('DisCrypt: Sidebar not found, retrying...');
                setTimeout(createGUI, 1000, callback);
                return;
            }

            const listItem = document.createElement('div');
            listItem.id = 'discrypt-settings-button';
            listItem.className = findClassNames('listItem');

            const listItemWrapper = document.createElement('div');
            listItemWrapper.className = findClassNames('listItemWrapper');

            const wrapper = document.createElement('div');
            wrapper.className = findClassNames('wrapper');
            wrapper.style.cssText = `
                cursor: pointer;
                position: relative;
                border-radius: 50%;
                width: 48px;
                height: 48px;
                display: flex;
                align-items: center;
                justify-content: center;
                background:rgb(45, 45, 46);
                transition: border-radius 0.2s ease, background 0.2s ease;
            `;

            wrapper.addEventListener('mouseenter', () => {
                wrapper.style.borderRadius = '16px';
                wrapper.style.background = '#4752C4';
            });

            wrapper.addEventListener('mouseleave', () => {
                wrapper.style.borderRadius = '50%';
                wrapper.style.background = 'rgb(45, 45, 46)';
            });

            wrapper.innerHTML = `
                <div style="font-size: 20px; line-height: 1;">🔐</div>
            `;

            wrapper.addEventListener('click', () => showPeerModal());

            listItemWrapper.appendChild(wrapper);
            listItem.appendChild(listItemWrapper);
            sidebarContainer.appendChild(listItem);
            createPeerSelectorUI();
            if (callback) callback();
        }

        function findClassNames(partialName) {
            const selectors = {
                'listItem': '[class*="listItem"]',
                'listItemWrapper': '[class*="listItemWrapper"]',
                'wrapper': '[class*="wrapper_"][class*="svg"]'
            };

            const element = document.querySelector(selectors[partialName]);
            if (element) {
                const classes = Array.from(element.classList)
                    .filter(c => c.includes(partialName.replace(/([A-Z])/g, '_$1').toLowerCase()) ||
                        c.includes(partialName));
                return classes.join(' ') || '';
            }
            return '';
        }

        function showPeerModal() {
            const modal = document.createElement('div');
            modal.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 10001;
            background: #2f3136;
            padding: 20px;
            border-radius: 8px;
            color: white;
            min-width: 400px;
            max-height: 80vh;
            overflow-y: auto;
        `;

            let myKeyHTML = '<h3 style="margin:0 0 2vh 0;">My Public Key</h3>';
            if (my_keypair) {
                const pubKeyB64 = encodeBase64(my_keypair.publicKey);
                myKeyHTML += `<div style="margin-bottom: 15px; padding: 10px; background: #40444b; border-radius: 4px; word-break: break-all;">
                <code style="color:rgb(104, 235, 245);user-select:all;">${pubKeyB64}</code>
                <button id="copyPubKeyBtn" style="display: block; margin-top: 8px; padding: 5px 10px; background: #5865F2; border: none; color: white; border-radius: 3px; cursor: pointer;">Copy to Clipboard</button>
            </div>`;
            } else {
                myKeyHTML += `<div style="margin-bottom: 15px;">
                <p style="color: #999;">No keypair generated yet.</p>
                <button id="generateKeyBtn" style="padding: 8px 15px; background: #5865F2; border: none; color: white; border-radius: 4px; cursor: pointer;">Generate Keypair</button>
            </div>`;
            }

            async function buildPeerList() {
                let peerListHTML = `<h3 style="margin: 0 0 1vh 0;">Known Peers</h3>
<div style="margin: 1vh 0; display: flex; flex-direction:column;align-items:center;justify-content:center;gap:1vw;padding:1vh 1vw;">`;
                for (let [user_id, pubKey] of Object.entries(known_peer)) {
                    const peerHash = await sha256(pubKey);
                    const peerId = `peer-${peerHash}`;
                    peerListHTML += `<div id="${peerId}" style="padding: 8px; background: #40444b; border-radius: 4px;">
                    <label>${user_id}</label>:<strong>${pubKey.substring(0, 20)}...</strong>
                    <button class="delete-peer-btn" data-user-peer="${pubKey}" style="float: right; background: #ed4245; border: none; color: white; padding: 2px 8px; border-radius: 3px; cursor: pointer;">Delete</button>
                </div>`;
                }
                peerListHTML += '</div>';
                return peerListHTML;
            }

            buildPeerList().then(peerListHTML => {
                modal.innerHTML = `
                ${myKeyHTML}
                ${peerListHTML}
                <h3>Add New Peer</h3>
                <input type="text" id="peerPubKey" placeholder="User id:Base64 Public Key (44 chars)" style="width: 95%; padding: 8px; margin: 5px 0; background: #40444b; border: 1px solid #202225; color: white; border-radius: 4px;">
                <button id="addPeerBtn" style="padding: 8px 15px; background: #3ba55d; border: none; color: white; border-radius: 4px; cursor: pointer; margin-top: 10px;">Add Peer</button>
                <button id="closeModalBtn" style="padding: 8px 15px; background: #ed4245; border: none; color: white; border-radius: 4px; cursor: pointer; margin-top: 10px; margin-left: 10px;">Close</button>
            `;

                setupModalEventListeners(modal, overlay);
            });

            const overlay = document.createElement('div');
            overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            z-index: 10000;
        `;

            document.body.appendChild(overlay);
            document.body.appendChild(modal);
        }

        function setupModalEventListeners(modal, overlay) {

            const generateBtn = document.getElementById('generateKeyBtn');
            if (generateBtn) {
                generateBtn.addEventListener('click', async () => {
                    const keypair = nacl.box.keyPair();

                    const keypairToSave = {
                        publicKey: encodeBase64(keypair.publicKey),
                        secretKey: encodeBase64(keypair.secretKey)
                    };

                    my_keypair = keypair;
                    save_keypair(keypairToSave);

                    overlay.remove();
                    modal.remove();
                    showPeerModal();
                });
            }

            const copyBtn = document.getElementById('copyPubKeyBtn');
            if (copyBtn) {
                copyBtn.addEventListener('click', () => {
                    if (!my_keypair) {
                        alert('Please generate a keypair first');
                        return;
                    }
                    const pubKeyB64 = encodeBase64(my_keypair.publicKey);
                    navigator.clipboard.writeText(pubKeyB64).then(() => {
                        const originalText = copyBtn.textContent;
                        copyBtn.textContent = 'Copied!';
                        setTimeout(() => { copyBtn.textContent = originalText; }, 2000);
                    });
                });
            }

            modal.querySelectorAll('.delete-peer-btn').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    const pubkey = e.target.dataset.userPeer;
                    const peerHash = await sha256(pubkey);
                    const peerId = `peer-${peerHash}`;
                    const user_id = Object.entries(known_peer).filter(x => { return x[1] == pubkey; })[0][0];

                    delete known_peer[user_id];
                    save_peers(known_peer);

                    const peerElement = document.getElementById(peerId);
                    if (peerElement) {
                        peerElement.remove();
                    }
                });
            });

            document.getElementById('addPeerBtn').addEventListener('click', () => {
                const input = document.getElementById('peerPubKey').value.trim();

                if (!input) {
                    alert('Please fill in the public key field');
                    return;
                }

                let splitted = input.split(":");
                if (splitted.length != 2) {
                    alert('Wrong format');
                    return;
                }
                let [user_id, pubKey] = splitted;

                if (!isValidEd25519PubKey(pubKey)) {
                    alert('Invalid public key. Must be a valid base64-encoded 32-byte key.');
                    return;
                }

                if (!/\d{17,20}/.exec(user_id)) {
                    alert("Invalid user id");
                    return
                }

                known_peer[user_id] = pubKey;
                save_peers(known_peer);
                overlay.remove();
                modal.remove();
                alert('Peer added successfully!');
            });

            document.getElementById('closeModalBtn').addEventListener('click', () => {
                overlay.remove();
                modal.remove();
            });
        }

        function observeMessages() {
            const chatContainer = document.querySelector('[class*="chatContent_"]');

            if (!chatContainer) {
                setTimeout(observeMessages, 500);
                return null;
            }

            processExistingMessages(chatContainer);

            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === 1 && node?.className?.startsWith && node?.className?.startsWith("flash__")) {//after a jumpToMessage call, it will create a flash div with the message inside.
                            return extractMessageData(node.querySelector("li"));
                        }
                        if (node.nodeType === 1 && node.id?.startsWith('chat-messages-')) {
                            return extractMessageData(node);
                        }
                        if (node.nodeType === 1 && node.id?.startsWith('message-content-')) {
                            return extractMessageData(node.closest("li[id^=chat-messages]"));
                        }
                    });
                });
            });

            observer.observe(chatContainer, {
                childList: true,
                subtree: true
            });

            return observer;
        }

        function processExistingMessages(chatContainer) {
            const existingMessages = chatContainer.querySelectorAll('[id^="chat-messages-"]');
            console.log(`DisCrypt: Processing ${existingMessages.length} existing messages...`);

            existingMessages.forEach(messageElement => {
                extractMessageData(messageElement);
            });
        }

        function watchForChannelChanges() {
            let currentObserver = observeMessages();
            let lastChatContainer = document.querySelector('[class*="chatContent_"]');
            let lastChannelId = null;

            const appMount = document.querySelector('#app-mount');
            if (!appMount) {
                console.error('DisCrypt: Could not find #app-mount');
                return;
            }

            const containerWatcher = new MutationObserver(() => {
                const newChatContainer = document.querySelector('[class*="chatContent_"]');
                if (newChatContainer && newChatContainer !== lastChatContainer) {
                    console.log('DisCrypt: Chat container changed, restarting observer...');
                    if (currentObserver) {
                        currentObserver.disconnect();
                    }
                    lastChatContainer = newChatContainer;
                    currentObserver = observeMessages();
                    detectCurrentChannel();
                }

                if (!document.querySelector('#discrypt-settings-button')) {
                    const sidebar = document.querySelector('[class*="scroller_"][class*="none_"]');
                    if (sidebar) {
                        createGUI();
                    }
                }
            });

            function detectCurrentChannel() {
                const channelID = get_url_channel_id();
                if (channelID && channelID !== lastChannelId) {
                    lastChannelId = channelID;
                    updatePeerSelector(channelID);
                }
            }

            // Watch for URL changes (channel switching)
            let lastUrl = window.location.href;
            new MutationObserver(() => {
                const currentUrl = window.location.href;
                if (currentUrl !== lastUrl) {
                    lastUrl = currentUrl;
                    detectCurrentChannel();
                }
            }).observe(document.body, { childList: true, subtree: true });

            detectCurrentChannel();

            containerWatcher.observe(appMount, {
                childList: true,
                subtree: true
            });

            console.log('DisCrypt: Channel watcher initialized');
        }

        createGUI(function () {
            //after creating the ui, update peer listing by checking url
            updatePeerSelector(get_url_channel_id());
        });
        watchForChannelChanges();

    }
})();
