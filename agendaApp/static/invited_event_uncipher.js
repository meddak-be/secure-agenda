window.onload = function() { //called when the html page is loaded
    const encryptedSymKey = document.getElementById('encrypted_sym_key').value;
    if (encryptedSymKey != ''){
    //uncipher all the fields for an invitation
    const user = document.getElementById('user_label').value;
    const symKey = decrypt(encryptedSymKey, user);
    decryptForm(symKey);
    }
  }


function decryptForm(key) {
  decryptElem("title", key);
  decryptElem("description", key);
  decryptElem("location", key);
  decryptElem("start_time", key);
  decryptElem("end_time", key);
}

function decryptElem(id, key){
  var field = document.getElementById(id).textContent;
  const decrypted = CryptoJS.AES.decrypt(field, key);
  const decryptedMessage = decrypted.toString(CryptoJS.enc.Utf8);
  document.getElementById(id).textContent = decryptedMessage;
}