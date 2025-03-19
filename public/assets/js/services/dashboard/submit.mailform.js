
export async function submitMail(event, url) {
    event.preventDefault()
    const formData = new FormData(event.target);
    let dataArray = []
    formData.forEach(data => {
      dataArray.push(data)
    })

    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const mailValidator = regex.test(dataArray[4]);
    if (mailValidator) {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 15000);
      try {
        const response = await fetch(`${url}logs/sendtable`, {
          method: 'POST',
          body: JSON.stringify({
            name: dataArray[0],
            surname: dataArray[1],
            'log-date': dataArray[2],
            type: dataArray[3],
            mail: dataArray[4],
            'form-hidden': dataArray[5]
          }),
          headers: {
            'Content-Type': 'application/json'
          },
          signal: controller.signal
        })
        if (response.status >= 200 && response.status < 400) {
              const result = await response.json();
              return {
                response,
                result
              }
            } else if (response.status >= 400 && response.status < 500 ) {
              const result = await response.json();
              return {
                response,
                result
              }
            } else {
              const result = response.json();
              return {
                response,
                result
              }
            }
      } catch (err) {
        console.error(err)
      }
    } else {
      return 'invalid mail';
    }

  

}

