
export function appendButtons(response) {
  if (document.querySelector(`.${response.logType}-request-container`)) {
    document.querySelector(`.${response.logType}-request-container`).remove();
  }
  try {  
    let div = document.createElement('div');
    let container = document.querySelector(`.${response.logType}-container`)
  
    container.append(div);
    let requestContainer = container.children[1];
    requestContainer.setAttribute('class', `${response.logType}-request-container`)
    requestContainer.innerHTML = `
      <div class="${response.logType}-download-container">
        <button class="${response.logType}-download-button">Download ${response.logType}s file</button>
      </div>
      <div class="${response.logType}-table-container">
        <button class="${response.logType}-table-button">Display ${response.logType}s table</button>
      </div>
    `;

    return true;
  } catch (err) {
    console.error(err)
  }
}

export function appendDelete(table) {
  const tBodyHtmlCollection = table.children[0].children[0].children[0].children
  let rowsArray = Array.from(tBodyHtmlCollection);
  rowsArray.forEach((value, index) => {
    if (index != 0) {
      const newValue = document.createElement('td');
      newValue.innerHTML = `<button class="delete-log" data-index="${index}">Delete</button>`;
      value.append(newValue)
    } else {
      const newValueHeader = document.createElement('th');
      newValueHeader.style.backgroundColor = '#4CAF50';
      value.append(newValueHeader)
    }
  })
}
