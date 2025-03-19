
export async function deleteLog(type, element, url) {
      element.dataset.index
      const bodyObject = {
        index: element.dataset.index,
        type: type
      }
      const response = await fetch(`${url}logs/deletelog`, {
        method: "POST",
        body: JSON.stringify(bodyObject),
        headers: {
          "Content-Type": "application/json"
        }
      })

      if (response.status >= 200 && response.status < 400) {
        const result = await response.json();
        return result
      } else if (response.status >= 400 && response.status < 500 ){
        const error = response;
        throw new Error(error)
      } else {
        const error = response;
        throw new Error(error);
      }
}