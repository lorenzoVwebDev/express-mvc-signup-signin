export async function get_dogtable(event, url) {
    const formData = new FormData(event.target);
    const response = await fetch(`${url}dog/insertdog`, {
      method: "POST",
      body: formData
    });

    if (response.status >= 200 && response.status < 400) {
      let dogArray = await response.text();
      return dogArray;
    } else if (response.status >= 400 && response.status < 500) {
      throw new Error('Bad Request');
    } else if (response.status >= 500) {
      throw new Error('Server Error')
    }
}