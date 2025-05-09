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

// 실시간 알림 처리
const socket = io();

socket.on('connect', () => {
    console.log('Socket.IO 연결됨');
});

socket.on('notification', (data) => {
    showNotification(data.message);
    updateNotificationBadge();
});

// 알림 표시 함수
function showNotification(message) {
    const alert = document.createElement('div');
    alert.className = 'alert alert-info alert-dismissible fade show';
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.querySelector('.container').insertBefore(alert, document.querySelector('.container').firstChild);
}

// 알림 배지 업데이트
function updateNotificationBadge() {
    const badge = document.querySelector('.notification-badge');
    if (badge) {
        const count = parseInt(badge.textContent) + 1;
        badge.textContent = count;
    }
}

// 좋아요 기능
document.addEventListener('DOMContentLoaded', () => {
    const likeButtons = document.querySelectorAll('.like-button');
    likeButtons.forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            const portfolioId = button.dataset.portfolioId;
            try {
                const response = await fetch(`/portfolio/${portfolioId}/like`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                const data = await response.json();
                if (data.success) {
                    const likeCount = button.querySelector('.like-count');
                    likeCount.textContent = data.likes;
                    button.classList.toggle('liked');
                }
            } catch (error) {
                console.error('좋아요 처리 중 오류 발생:', error);
            }
        });
    });
});

// 검색 기능
const searchForm = document.querySelector('.search-form');
if (searchForm) {
    searchForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const query = searchForm.querySelector('input[name="q"]').value;
        window.location.href = `/search?q=${encodeURIComponent(query)}`;
    });
}

// 이미지 미리보기
const imageInput = document.querySelector('input[type="file"]');
if (imageInput) {
    imageInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                const preview = document.querySelector('.image-preview');
                if (preview) {
                    preview.src = e.target.result;
                    preview.style.display = 'block';
                }
            };
            reader.readAsDataURL(file);
        }
    });
}

// 메시지 전송
const messageForm = document.querySelector('.message-form');
if (messageForm) {
    messageForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const content = messageForm.querySelector('textarea[name="content"]').value;
        const receiverId = messageForm.dataset.receiverId;
        
        try {
            const response = await fetch('/messages/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    content,
                    receiver_id: receiverId
                })
            });
            
            const data = await response.json();
            if (data.success) {
                messageForm.reset();
                const messageList = document.querySelector('.message-list');
                if (messageList) {
                    const messageElement = document.createElement('div');
                    messageElement.className = 'message sent';
                    messageElement.innerHTML = `
                        <div class="message-content">${content}</div>
                        <div class="message-time">${new Date().toLocaleTimeString()}</div>
                    `;
                    messageList.appendChild(messageElement);
                    messageList.scrollTop = messageList.scrollHeight;
                }
            }
        } catch (error) {
            console.error('메시지 전송 중 오류 발생:', error);
        }
    });
} 