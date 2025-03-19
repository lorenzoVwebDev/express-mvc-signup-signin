export function signInView(result, response, url, event) {
  if (response.status >= 200 && response.status < 400) {
    window.location.href = url;
  } else if (response.status >= 400 && response.status < 500) {
    event.target.children[0].children[0].remove()
    const h3 = document.createElement('h3')
    h3.innerText = result['result'];
    h3.style.color = 'red';
    event.target.children[0].prepend(h3)
    throw new Error(`${result.result}`)
  } else if (response.status >= 500 ) {
    event.target.children[0].children[0].remove()
    const logInForm = event.target.children[0]
    logInForm.innerHTML = '';
    const h1 = document.createElement('h1')
    h1.innerText = result['result'] + ' Please, try to log in again';
    logInForm.append(h1);
    setTimeout(() => {
      window.location.href = `${url}authentication/view`;
    }, 3000)
    throw new Error('Server error occured');
  }
}

export function signUpView(result, response, url, event) {
  if (response.status >= 200 && response.status < 400) {
    const parent = event.target.parentElement
    parent.innerHTML = "";
    const h1 = document.createElement('h1');
    h1.innerText = "Thank you so much for signing up!";
    parent.append(h1);
    setTimeout(() => {
      window.location.href = `${url}authentication/authentication/signin`
    }, 4000)
  } else if (response.status >= 400 && response.status < 500) {
    event.target.reset()
    if (document.getElementById('h2-message')) {
      document.getElementById('h2-message').remove();
    }
    const h2 = document.createElement('h2');
    h2.setAttribute('id', 'h2-message')
    h2.innerText = `Username exists yet`;
    h2.style.color = 'red';
    event.target.prepend(h2)
    throw new Error(`${result.result}`)
  } else if (response.status >= 500 ) {
    const parent = event.target.parentElement
    parent.innerHTML = "";
    const h1 = document.createElement('h1');
    h1.innerText = `${result.result}`;
    parent.append(h1);
    setTimeout(() => {
      window.location.href = `${url}`;
    }, 3000)
    throw new Error('Server error occured');
  }
}


export function changepwrView(result, response, url, event) {
  if (response.status >= 200 && response.status < 400) {
    const parent = event.target.parentElement
    parent.innerHTML = "";
    const h1 = document.createElement('h1');
    h1.innerText = `${result.message}`;
    parent.append(h1);
    setTimeout(() => {
      window.location.href = `${url}authentication/authentication/signin`
    }, 3000)
  } else if (response.status >= 400 && response.status < 500) {
    event.target.reset()
    if (document.getElementById('h2-message')) {
      document.getElementById('h2-message').remove();
    }
    const h2 = document.createElement('h2');
    h2.setAttribute('id', 'h2-message')
    h2.innerText = `!! ${result.result} !!`;
    h2.style.color = 'red';
    event.target.prepend(h2)
    throw new Error(`${result.result}`)
  } else if (response.status >= 500 ) {
    const parent = event.target.parentElement
    parent.innerHTML = "";
    const h1 = document.createElement('h1');
    h1.innerText = `${result.result}`;
    parent.append(h1);
    setTimeout(() => {
      window.location.href = `${url}`;
    }, 3000)
    throw new Error('Server error occured');
  }
}