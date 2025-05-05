document.addEventListener('DOMContentLoaded', function() {
    const btn = document.getElementById('darkmode-toggle');
    if (btn) {
        btn.onclick = function() {
            document.body.classList.toggle('darkmode');
            // 로컬스토리지에 저장
            if(document.body.classList.contains('darkmode')) {
                localStorage.setItem('darkmode', '1');
            } else {
                localStorage.removeItem('darkmode');
            }
        };
        // 페이지 로드 시 다크모드 적용
        if(localStorage.getItem('darkmode')) {
            document.body.classList.add('darkmode');
        }
    }
}); 