const alert = (msg, location = null )=>{ // ES6 Default Value 지정 가능
  return `
  <script>
  alert('${msg}');
  ${location ? "location.href = '" + location + "';" : ""}
  </script>`;
}
const imgExt = ['.jpg', '.jpeg', '.png', '.gif'];
const allowExt = [...imgExt, '.pdf', '.zip'];

module.exports = { alert, imgExt, allowExt }