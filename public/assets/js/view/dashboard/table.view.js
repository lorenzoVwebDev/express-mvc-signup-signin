export function createTableAndMail(response, result) {
  if (response.status >= 200 && response.status<400) {
    if (document.querySelector('.admin-table-section')) {
      document.querySelector('.admin-table-section').innerHTML = '';
    }
    let table = document.querySelector('.admin-table-section')
    let div = document.createElement('div');
    let mailFormDiv = document.createElement('div');
    mailFormDiv.classList.add('mail-form-container');
    div.classList.add('table-container')
    div.innerHTML = result;
    table.append(div);
    return table
  } else if (response.status >= 400 && response.status < 500) {
    var modal = document.querySelector('.modal-container')
    modal.style.display = 'block';
    var modalTitle = document.getElementById('modal-title')
    var modalText = document.getElementById('modal-text')
    modalTitle.innerText = `Error ${result.status.toString()}`;
    modalText.innerHTML = `${result.result}, try another date`
    var modalText = document.getElementById('')
  } else if (response.status >= 500) {
    var modal = document.querySelector('.modal-container')
    modal.style.display = 'block';
    var modalTitle = document.getElementById('modal-title')
    var modalText = document.getElementById('modal-text')
    modalTitle.innerText = `Error ${result.status.toString()}`;
    modalText.innerHTML = `${result.result}`
    var modalText = document.getElementById('')
  }
}

