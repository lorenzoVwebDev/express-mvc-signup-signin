import "https://cdn.jsdelivr.net/npm/dayjs@1/dayjs.min.js";
import { url } from '../../../utils/globalVariables.js'


let modal = `
<div class="modal modal-sheet position-static d-block p-4 py-md-5" tabindex="-1" role="dialog" id="modalSignin">
  <script src="${url}assets/js/services/home/get_breeds.js"></script>
    <div class="modal-dialog" role="document">
      <div class="modal-content rounded-4 shadow">
        <div class="modal-header p-5 pb-4 border-bottom-0">
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close" id="close-button"></button>
        </div>
  
        <div class="modal-body p-5 pt-0">
            <form id="update-dog-form" class="update-dog-form">
                <fieldset>
                    <div class="form-floating mb-3">
                      <input class="form-control rounded-3" type="text" maxlength="20" placeholder="Use up to 20 characters for the name" name="dog_name" id="dog_name" value="lorenzo" required/>
                      <label for="dog_name">Dogname:</label>
                    </div>
                    <div class="mb-3">
                      <div class="radio-container">
                      <div class="radio-name-container">
                        <span>Brown</span>
                        <span>black</span>
                        <span>yellow</span>
                        <span>white</span>
                        <span>mixed</span>
                      </div>
                      <div class="radio-input-container" required>
                        <input type="radio" name="dog_color" id="dog_color" value="brown" checked/><br/>
                        <input type="radio" name="dog_color" id="dog_color" value="black"/><br/>
                        <input type="radio" name="dog_color" id="dog_color" value="yellow"/><br/>
                        <input type="radio" name="dog_color" id="dog_color" value="white"/><br/>
                        <input type="radio" name="dog_color" id="dog_color" value="mixed"/><br/><br/>
                      </div>
                    </div>
                    </div>
                    <div class="mb-3">
                      <div id="AjaxResponseModal"></div>
                    </div>
                    <div class="mb-3">
                      <input type="number" min="0" max="120" name="dog_weight" id="dog_weight" value="15" required/>
                      <label for="dog_weight">Weigth</label>
                    </div>
                    <div class="form-actions form-floating mb-3">
                    <input type="hidden" name="task" id="task" value="task"/>
                    <button class="w-100 mb-2 btn btn-lg rounded-3 btn-primary" type="submit" id="submit-button">Update</button>
                    </div>
                </fieldset>
            </form>
        </div>
      </div>
    </div>
  </div>
`

export default modal;






