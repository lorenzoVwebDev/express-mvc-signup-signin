
export async function downloadTable(type, date, url){
    const response = await fetch(`${url}logs/table?type=${type}&date=${date}`)

    if (response.status >= 200 && response.status < 400) {
      const result = await response.text();
      return {
        response,
        result
      }
    } else if (response.status >= 400 && response.status < 500 ){
      const result = await response.json();
      return {
        response,
        result
      }
    } else {
      const result = await response.json();
      return {
        response,
        result
      }
    }
}