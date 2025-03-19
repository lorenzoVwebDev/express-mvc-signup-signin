export async function renderResponse(response = {
  status: 0
}, result) {
  if (response === 'invalid mail') {
    if (document.querySelector('.error-log-message')) {
      document.querySelector('.error-log-message').remove()
      } 
      let div = document.createElement('div')
      div.classList.add('error-log-message');
      let h2 = document.createElement('h2');
      let h3 = document.createElement('h3');
      h2.innerHTML = 'mail not valid' +'\n';
      h3.innerHTML+= 'Please, insert another mail'
      h3.style.textAlign = 'center';
      h2.style.textAlign = 'center';
      h2.style.color = 'red';
      h3.style.color = 'red';
      div.append(h2, h3)
      document.querySelector('.mail-section').append(div);
      return
  }

  if (response.status >= 200 && response.status < 400) {
    if (document.querySelector('.error-log-message')) {
      document.querySelector('.error-log-message').remove()
      } 
      let div = document.createElement('div')
      div.classList.add('error-log-message');
      let h2 = document.createElement('h2');
      h2.innerHTML = `${result.message}`;
      h2.style.textAlign = 'center';
      h2.style.color = 'green';
      div.append(h2)
      document.querySelector('.mail-section').append(div);
      return;
  } else if (response.status >= 400 && response.status < 500 ) {
    if (response.status === 409) {
      if (document.querySelector('.error-log-message')) {
        document.querySelector('.error-log-message').remove()
        } 
        let div = document.createElement('div')
        div.classList.add('error-log-message');
        let h2 = document.createElement('h2');
        let h3 = document.createElement('h3');
        h2.innerHTML = '!!'+ result.result + '!!' +'\n';
        h3.innerHTML+= 'You have reached the max mail deliverings'
        h3.style.textAlign = 'center';
        h2.style.textAlign = 'center';
        h2.style.color = 'red';
        h3.style.color = 'red';
        div.append(h2, h3)
        document.querySelector('.mail-section').append(div);
        return;
    }

    if (document.querySelector('.error-log-message')) {
      document.querySelector('.error-log-message').remove()
    } 
      let div = document.createElement('div')
      div.classList.add('error-log-message');
      let h2 = document.createElement('h2');
      let h3 = document.createElement('h3');
      h2.innerHTML = '!!'+result.result + '!!' +'\n';
      h3.innerHTML+= 'Try another date, or create a current log file below'
      h3.style.textAlign = 'center';
      h2.style.textAlign = 'center';
      h2.style.color = 'red';
      h3.style.color = 'red';
      div.append(h2, h3)
      document.querySelector('.mail-section').append(div);
  }
}