function onSubmit(f){
  if(f.id){
    f.action = '/board/put';
  }
  else{
    f.action = '/board/save';
  }

  if(f.title.value.trim() === "")
  {
    alert("제목을 입력하세요");
    f.title.focus();
    return false;
  }
  if(f.writer.value.trim() === "")
  {
    alert("작성자를 입력하세요");
    f.writer.focus();
    return false;
  }
  if(f.comment.value.trim() === "")
  {
    alert("내용을 입력하세요");
    f.comment.focus();
    return false;
  }
  return true;
}

document.querySelectorAll('.board-link').forEach((v)=>{
  // console.log(v.dataset.id);
  v.addEventListener('click', function(){
    location.href = '/board/view/' + this.dataset.id;
  })
});

function rmFile(id){
  if(confirm('첨부파일을 삭제하시겠습니까?')){
    axios.get('/board/rm-file/' + id)
    .then(function(res){
      console.log(res.data.code);
      if(res.data.code == 200) document.querySelector('.savefile').innerHTML = '';
      else alert('파일을 삭제하지 못했습니다. 다시 시도해 주세요.');
    })
    .catch(function(err){
      console.log(err);
    });
  }
}