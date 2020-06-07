const fs = require('fs');
const path = require('path');
const moment = require('moment');
const multer = require('multer');
const {allowExt, imgExt} = require('./utils');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, makeFolder());
  },
  filename: function (req, file, cb) {
    // cb(null, file.fieldname + '-' + Date.now())
    cb(null, makeFile(file));
  }
});

const upload = multer({storage, fileFilter, limits:{fileSize : 2048000}}); // 2MB 용량 제한

function makeFile(file) {
	let oriName = file.originalname;	// abc.jpg
	let ext = path.extname(oriName);	// .jpg
	//200531-1523293823459-234.jpg
	let newName = moment().format('YYMMDD') + '-' + Date.now() + '-' + Math.floor((Math.random() * 900 + 100)) + ext;
	return newName;
};

function makeFolder() {
	const folderName = moment().format("YYMMDD"); //200531
	const newPath = path.join(__dirname, "../upload/"+folderName);
	if(!fs.existsSync(newPath)) {
		fs.mkdir(newPath, (err) => {
			if(err) new Error(err);
			return newPath;
		});
	}
	return newPath;
}

function fileFilter(req, file, cb) {
  // const allowExt = ['.jpg', '.jpeg', '.gif', '.png', '.pdf', '.zip'];
  const ext = path.extname(file.originalname).toLowerCase();

  if(allowExt.indexOf(ext) > -1){
    cb(null, true);
  }
  else{
    req.fileCheck = ext.substr(1); // 확장자에서 .을 뺀 나머지
    cb(null, false);
  }
  allowExt.indexOf(ext) > -1 ? cb(null, true) : cb(null, false);
}

function serverPath(fPath){
  return filePath = path.join(__dirname, '../upload/', fPath.substr(0, 6), fPath);
}

function clientPath(fPath){
  return filePath = path.join('/storage/', fPath.substr(0, 6), fPath);
}

function imgSrc(file){
  if(imgExt.indexOf(path.extname(file).toLowerCase()) > -1){
    return '/storage/' + file.substr(0, 6) + '/' + file;
  }
  else return null;
}

module.exports = {upload, serverPath, clientPath, imgSrc};