import "https://cdn.jsdelivr.net/npm/dayjs@1/dayjs.min.js";

export async function downloadLogFile(type, date,serverUrl) {
  const response = await fetch(`${serverUrl}logs/downloadlogs/${type}?type=${type}&date=${date}`);

  if (response.status >= 200 && response.status<400) {
    const result = await response.blob();
    return {
      response,
      result
    }
  } else if (response.status >= 400 && response.status < 500) {
    const result = await response.json();
    return {
      response,
      result
    }
  } else if (response.status >= 500) {
    const result = await response.json();
    return {
      response,
      result
    }
  }
}


/* fetch(`http://logs-table-reader-mvc/public/download/downloadlogs/exception?potato=4&carrot=5/`, {
  headers: {
    "Content-Type": "application/json"
  }
}).then(response => response.json());

 */