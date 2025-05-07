import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { userService, UserInfo } from '../services/userService';
import './MyPage.css';

const MyPage: React.FC = () => {
  const navigate = useNavigate();
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchUserInfo = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await userService.getUserInfo();
      setUserInfo(data);
    } catch (error) {
      setError(error instanceof Error ? error.message : '사용자 정보를 불러오는데 실패했습니다.');
      if (error instanceof Error && error.message.includes('인증이 만료')) {
        navigate('/login');
      }
    } finally {
      setIsLoading(false);
    }
  }, [navigate]);

  const handleLogout = useCallback(async () => {
    try {
      await userService.logout();
      navigate('/login');
    } catch (error) {
      setError(error instanceof Error ? error.message : '로그아웃 중 오류가 발생했습니다.');
      // 로그아웃 실패 시에도 로그인 페이지로 이동
      navigate('/login');
    }
  }, [navigate]);

  useEffect(() => {
    fetchUserInfo();
  }, [fetchUserInfo]);

  if (isLoading) {
    return (
      <div className="container" role="main">
        <div className="loading-spinner" role="status" aria-label="로딩 중">
          <span className="sr-only">로딩 중입니다...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="container" role="main">
      <div className="card">
        <h1 className="title">마이페이지</h1>
        {error && (
          <div className="error-message" role="alert" aria-live="assertive">
            {error}
          </div>
        )}
        {userInfo ? (
          <>
            <div className="info-row">
              <span className="label">이름</span>
              <span className="value">{userInfo.name}</span>
            </div>
            <div className="info-row">
              <span className="label">이메일</span>
              <span className="value">{userInfo.email}</span>
            </div>
            <div className="info-row">
              <span className="label">가입일</span>
              <span className="value">{new Date(userInfo.createdAt).toLocaleDateString()}</span>
            </div>
            <div className="info-row">
              <span className="label">역할</span>
              <span className="value">{userInfo.role === 'freelancer' ? '프리랜서' : '클라이언트'}</span>
            </div>
            <div className="info-row">
              <span className="label">인증 상태</span>
              <span className="value">{userInfo.isVerified ? '인증됨' : '미인증'}</span>
            </div>
            <button 
              className="button" 
              onClick={handleLogout}
              aria-label="로그아웃"
            >
              로그아웃
            </button>
          </>
        ) : (
          <div className="error-message" role="alert" aria-live="assertive">
            사용자 정보를 불러올 수 없습니다.
          </div>
        )}
      </div>
    </div>
  );
};

export default MyPage; 