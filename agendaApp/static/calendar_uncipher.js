
window.onload = function() { //called when the html page is loaded
    const user = document.getElementById('user_label').textContent;
    if (sessionStorage.getItem(user + "PrKey") == null){
        window.location.href = '/logout/';
    }
    const links = document.querySelectorAll('.event_title');
    //loop through all the titles to decrypt them
    for (let i = 0; i < links.length; i++) {
        const link = links[i];
        const key = link.dataset.key;
        const title = link.textContent;
        const symKey = decrypt(key, user);
        const decrypted = CryptoJS.AES.decrypt(title, symKey);
        const decryptedMessage = decrypted.toString(CryptoJS.enc.Utf8);
        link.textContent = decryptedMessage;

        //verify the signature
        const pubK = link.dataset.pubkey;
        const desc = link.dataset.desc;
        const loc = link.dataset.loc;
        const start = link.dataset.start;
        const end = link.dataset.end;
        const signedEvent = link.dataset.sign;
        const data = title+desc+loc+start+end;

        var sign = new JSEncrypt();
        sign.setPublicKey(pubK);
        var isValid = sign.verify(data, signedEvent, CryptoJS.SHA256);
        var iconHTML = "";
        if (isValid) {
            iconHTML = '<i class="fas fa-check text-success"></i>';
        } else {
            iconHTML = '<i class="fas fa-times text-danger"></i>';
        }
        link.innerHTML += iconHTML;
    }
  }

