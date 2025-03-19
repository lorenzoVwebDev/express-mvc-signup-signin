
export function renderNewDog(result, response) {
  if (response.status >= 200 && response.status<400) {
    const {dogname, dogbreed, dogcolor, dogweight, index} = result;
    const taskContainer = document.getElementById('doglist');
    const taskDiv = document.createElement('div');
    taskDiv.classList.add('dog');
  
    taskDiv.innerHTML = `
    <div class="dog-container">
      <div class="dog-info">
        <strong>${dogname}</strong>
        <p>Breed: ${dogbreed}</p>
        <small>Color: ${dogcolor}</small>
        <small>Weight: ${dogweight}</small>
      </div>
      <div class="dog-actions" data-id=${index}>
        <button class="update-dog">Edit</button>
        <button class="delete-dog">Delete</button>
      </div>  
    </div>
    `
  //
    taskContainer.append(taskDiv);
  } else if (response.status >= 400 && response.status < 500) {
    var modal = document.querySelector('.modal-container');
    modal.style.display = 'block';
    var modalTitle = document.getElementById('modal-title');
    var modalText = document.getElementById('modal-text');
    modalTitle.innerText = `Error ${result.status.toString()}`;
    modalText.innerHTML = `${result.result}`;
  } else if (response.status >= 500) {
    var modal = document.querySelector('.modal-container');
    modal.style.display = 'block';
    var modalTitle = document.getElementById('modal-title');
    var modalText = document.getElementById('modal-text');
    modalTitle.innerText = `Error ${result.status.toString()}`;
    modalText.innerHTML = `${result.result}`;
  }
}

export function renderStoredDog(result, response) {
  if (response.status >= 200 && response.status<400) {
    const taskContainer = document.getElementById('doglist');
    taskContainer.innerHTML = '';
    const resultArray = Object.entries(result);

    resultArray.forEach((element)=> {
        const task = `
        <div class="dog-container">
          <div class="dog-info">
            <strong>${element[1].dogname}</strong>
            <p>Breed: ${element[1].dogbreed}</p>
            <small>Color: ${element[1].dogcolor}</small>
            <small>Weight: ${element[1].dogweight}</small>
          </div>
          <div class="dog-actions" data-id=${element[0]}>
            <button class="update-dog">Edit</button>
            <button class="delete-dog">Delete</button>
          </div>
        </div>  
      `
        taskContainer.innerHTML += task;
    })
  } else if (response.status >= 400 && response.status < 500) {
    console.log('works')
    var modal = document.querySelector('.modal-container');
    modal.style.display = 'block';
    var modalTitle = document.getElementById('modal-title');
    var modalText = document.getElementById('modal-text');
    modalTitle.innerText = `Error ${result.status.toString()}`;
    modalText.innerHTML = `${result.result || result.result}`;
    throw new Error(result.status.toString())
  } else if (response.status >= 500) {
    var modal = document.querySelector('.modal-container');
    modal.style.display = 'block';
    var modalTitle = document.getElementById('modal-title');
    var modalText = document.getElementById('modal-text');
    modalTitle.innerText = `Error ${result.status.toString()}`;
    modalText.innerHTML = `${result.result}`;
    throw new Error(result.status.toString())
  }
}

export function renderEditModal() {
  var modal = document.querySelector('.edit-modal-container');
  modal.style.display = 'block';
  document.getElementById('close-button').addEventListener('click', () => {
    console.log('hello')
    modal.style.display = 'none';
  })
  return modal;
}





