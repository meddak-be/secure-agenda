window.onload = function() { //called when the html page is loaded
    const title = document.getElementById('id_title').value;
    if (title != ''){
      //uncipher all the data
      const user = document.getElementById('user_label').value;
      const symKeyEncrypted = document.getElementById('sym_key').value;
      const symKey = decrypt(symKeyEncrypted, user);
      decryptForm(document.getElementById('user_label').value, symKey);
    }
  }
  
function decryptForm(username, key) {
    decryptElem("id_title", key);
    decryptElem("id_description", key);
    decryptElem("id_location", key);
    decryptElem("id_start_time", key);
    decryptElem("id_end_time", key);
  }
  
  
function decryptElem(id, key){
  var field = $("#"+id).val();
  const decrypted = CryptoJS.AES.decrypt(field, key);
  const decryptedMessage = decrypted.toString(CryptoJS.enc.Utf8);
  document.getElementById(id).value = decryptedMessage;
}


function submitForm(event) {
    event.preventDefault();
    
    // Get the form data
    const form = event.target;
    const formData = new FormData(form);
    const userLabel = document.getElementById('user_label').value
    const symKeyEncrypted = document.getElementById('sym_key').value;
    var symKey;
    
    if (symKeyEncrypted == "None"){
    //generate a symmetric key
      const keyObj = CryptoJS.lib.WordArray.random(32);
      symKey = keyObj.toString(CryptoJS.enc.Hex);

      //add it to the form to save it to the database
      const keyField = document.createElement('input');
      keyField.type = 'hidden';
      keyField.name = 'symKey';
      data = encrypt(symKey, userLabel);
      keyField.value = data; 
      form.appendChild(keyField);
    } else {
      symKey = decrypt(symKeyEncrypted, userLabel);
    }
    //encrypt the data
    var data = '';
    for (const [key, value] of formData) {
      //cipher everything but:
      //  - the token
        
      if (key != "csrfmiddlewaretoken") {
        encryptedVal = CryptoJS.AES.encrypt(value, symKey);
        data += encryptedVal;
        formData.set(key, encryptedVal);
      }
      
    }
    //sign the event
    var sign = new JSEncrypt();
    sign.setPrivateKey(sessionStorage.getItem(userLabel + "PrKey"))
    var signedEvent = sign.sign(data, CryptoJS.SHA256, "sha256");

    const signedEv = document.createElement('input');
    signedEv.type = 'hidden';
    signedEv.name = 'signedEvent';
    signedEv.value = signedEvent; 
    form.appendChild(signedEv);


    for (const [key, value] of formData.entries()) {
        const input = form.querySelector(`[name="${key}"]`);
        if (input) {
            input.value = value;
        }
      }

    return form.submit();
}

