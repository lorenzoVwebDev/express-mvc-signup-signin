const path = require('path')
const fs = require('fs');
const glob  = require('glob');
const fsPromises = require('fs').promises;
const sass = require('sass');
const dayjs = require('dayjs');

const stylefiles = fs.readdirSync('./public/assets/css/scss')
function runListen() {
  stylefiles.forEach(async file => {
      if (file.includes('.scss')) {
        fs.watch(`./public/assets/css/scss/${file}`, async (event, filename) => {
          console.log(file)
          try {
            const compiledSass = sass.compile(path.join(__dirname, '../', '../', 'css','scss', file));
            const cssFile = file.replace('.scss', '.css')
            await fsPromises.writeFile(path.join(__dirname, '../', '../', 'css', cssFile), compiledSass.css);
          } catch (err) {
            console.log('attention! compiling error happened, check the scssError.log file')
            const errorText = dayjs().format() + "\n" + err.message;
            fsPromises.writeFile(path.join(__dirname, '../', '../', '../', '../', 'logs', 'scss','scssError.log'), errorText);
          }
        })
      }
  })
}

runListen()
 