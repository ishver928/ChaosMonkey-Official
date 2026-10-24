function vulnInner(el, comment) {
  el.innerHTML = '<p>' + comment + '</p>' // expect: CM-J001
}

function vulnTemplate(el, name) {
  el.innerHTML = `<b>${name}</b>` // expect: CM-J001
}

function vulnWrite(params) {
  document.write(params.get('q')) // expect: CM-J001
}

function vulnAdjacent(list, item) {
  list.insertAdjacentHTML('beforeend', item.html) // expect: CM-J001
}

function vulnJquery(msg) {
  $('#out').html(msg) // expect: CM-J001
}

function safeText(el, name) {
  el.textContent = name
}

function safeSanitized(el, html) {
  // fp-fixed: sanitized markup is the recommended way to use innerHTML
  el.innerHTML = DOMPurify.sanitize(html)
}

function safeLiteral(el) {
  el.innerHTML = '<p>Loading</p>'
}

function safeClear(el) {
  el.innerHTML = ''
}

function safeStaticTemplate(el) {
  el.innerHTML = `<p>Loading</p>`
}
