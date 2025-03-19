import {url} from '../utils/globalVariables.js'

window.addEventListener('load', () => {
  if (document.getElementById('log-out-button')) {
    document.getElementById('log-out-button').addEventListener('click', async (event) => {
      const responseObject = await fetch(`${url}authentication/logout/access`, {
        method: 'DELETE'
      })
      
      if (responseObject.status >= 200) {
        const response = await responseObject.json();
        document.cookie.split("; ").forEach(cookie => {
          if (cookie.includes("jwtRefresh=")) {
              document.cookie = "jwtRefresh=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
          }
      });
      
        window.location.href = url;
      }
    
    })
  }
})
