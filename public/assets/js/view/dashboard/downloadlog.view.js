export function downloadLogFileView(response, result, type) {
  if (response.status >= 200 && response.status<400) {
    const url = window.URL.createObjectURL(result);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${dayjs().format('DDMMYY')}${type}_logs.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
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