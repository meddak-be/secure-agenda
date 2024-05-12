function submitForm(event) {
    event.preventDefault();
  
    // Get the form data
    const form = event.target;
    const formData = new FormData(form);
    //set the data for the form to be sent
    const hash_old = CryptoJS.SHA256(formData.get("old_password")).toString();
    const hash_new = CryptoJS.SHA256(formData.get("password")).toString();
    const hash_confirm = CryptoJS.SHA256(formData.get("confirm_password")).toString();
    formData.set("old_password", hash_old);
    formData.set("password", hash_new);
    formData.set("confirm_password", hash_confirm);

      // Update the form with the modified form data
      for (const [key, value] of formData.entries()) {
        const input = form.querySelector(`[name="${key}"]`);
        if (input) {
            input.value = value;
        }
    }

    // Submit the form
    return form.submit();
  }