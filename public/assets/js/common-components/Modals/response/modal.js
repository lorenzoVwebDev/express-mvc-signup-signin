import { url } from '../../../utils/globalVariables.js'

let modal = `
    <div class="modal modal-sheet position-static d-block p-4 py-md-5" tabindex="-1" role="dialog" id="modalSheet">
      <div class="modal-dialog" role="document">
        <div class="modal-content rounded-4 shadow">
          <div class="modal-header border-bottom-0">
            <h1 class="modal-title fs-5" id="modal-title"></h1>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close" onclick="
              document.querySelector('.modal-container').style.display = 'none';
            "></button>
          </div>
          <div class="modal-body py-0">
            <p id="modal-text"></p>
          </div>
          <div class="modal-footer flex-column align-items-stretch w-100 gap-2 pb-3 border-top-0">
            <button type="button" class="btn btn-lg btn-secondary" data-bs-dismiss="modal" onclick="
              document.querySelector('.modal-container').style.display = 'none';
            ">Close</button>
          </div>
        </div>
      </div>
`

export default modal;