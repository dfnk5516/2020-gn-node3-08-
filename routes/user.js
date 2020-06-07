const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const {alert} = require('../modules/utils');
const {pool} = require('../modules/mysql-conn');
const pugVals = {cssFile : 'user', jsFile : 'user'}

router.get('/login', (req,res,next)=>{
  res.render('user/login', pugVals);
});
router.get('/logout', (req,res,next)=>{
  res.render('user/logout', pugVals);
});
router.get('/join', (req,res,next)=>{
  res.render('user/join', pugVals);
});
router.post('/save', async(req,res,next)=>{
  let {userid, userpw, username, email} = req.body;
  console.log(userpw);
  console.log(process.env.PASS_SALT)
  userpw = await bcrypt.hash(userpw + process.env.PASS_SALT, Number(process.env.PASS_ROUND));
  let connect, sql, result, sqlVals;
  try{
    connect = await pool.getConnection();
    sql = 'INSERT INTO user SET userid=?, userpw=?, username=?, email=?';
    sqlVals = [userid, userpw, username, email];
    result = await connect.query(sql, sqlVals);
    connect.release();
    res.redirect('/');
  }
  catch(e){
    connect.release();
    next(e);
  }
});

router.post('/auth', async(req,res,next)=>{
  let{userid, userpw} = req.body;
  let sql, connect, result;
  try{
    if(userid != "" && userpw !=""){
      connect = await pool.getConnection();
      sql = 'SELECT userpw FROM user WHERE userid=?';
      result = await connect.query(sql, [userid]);
      if(result[0][0]){
        result = await bcrypt.compare(userpw + process.env.PASS_SALT, result[0][0].userpw);
        connect.release();
        if(result){
          res.send(alert('회원입니다. 반갑습니다.'));
        }
        else{
          res.send(alert('아이디와 패스워드를 확인하세요', '/'));
        }
      }
      else{
        connect.release();
        res.send(alert('아이디와 패스워드를 확인하세요', '/'));
      }
    }
    else res.send(alert('아이디와 패스워드를 확인하세요', '/'));
  }
  catch(e){
    connect.release();
    next(e);
  }
});

module.exports = router;