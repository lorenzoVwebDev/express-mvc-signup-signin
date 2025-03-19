export async function insertDog(event, url) {
  const formData = new FormData(event.target);
  
  const response = await fetch(`${url}/dog/dogcrud/insert`, {
    method: 'POST',
    body: formData
  });

  if (response.status >= 200 && response.status < 400) {
    const result = await response.json()
    return {
      result,
      response
    }
  } else if (response.status >= 400 && response.status < 500) {
    const result = await response.json();
    return {
      result, response
    }
  }
}

export async function selectDog(url, id) {
  const response = await fetch(`${url}/dog/dogcrud/select?id=${id}`);
  
  if (response.status >= 200 && response.status < 400) {
    const result = await response.json()
    return {
      result,
      response
    }
  } else if (response.status >= 400 && response.status < 500) {
    const result = await response.json();
    return {
      result, response
    }
  }
}


export async function deleteDog(url, id) {
  const response = await fetch(`${url}/dog/dogcrud/delete/${id}`, {
    method: 'DELETE'
  });
  
  if (response.status >= 200 && response.status < 400) {
    const result = await response.text()
    return true
  } else if (response.status >= 400 && response.status < 500) {
    const result = await response.text();
    return false;
  } else if (response.status >= 500) {
    const result = await response.text();
    return false;
  }
}

export async function updateDog(url, form) {
  let formObject = {};
  form.forEach((input, key) => {
    formObject[key] = input
  })

  const response = await fetch(`${url}/dog/dogcrud/update`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(formObject)
  });

  if (response.status >= 200 && response.status < 400) {
    const result = await response.json()
    return {
      result,
      response
    }
  } else if (response.status >= 400 && response.status < 500) {
    const result = await response.json();
    return {
      result, response
    }
  } else if (response.status >= 500) {
    const result = await response.json();
    return {
      result, response
    }
  }
}