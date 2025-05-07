import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;

export interface UserInfo {
  id: number;
  name: string;
  email: string;
  createdAt: string;
  role: string;
  isVerified: boolean;
}

export interface ApiError {
  message: string;
  status: number;
}

class UserService {
  private static instance: UserService;
  private token: string | null = null;

  private constructor() {
    this.token = localStorage.getItem('token');
  }

  public static getInstance(): UserService {
    if (!UserService.instance) {
      UserService.instance = new UserService();
    }
    return UserService.instance;
  }

  private getHeaders() {
    return {
      Authorization: `Bearer ${this.token}`,
    };
  }

  public setToken(token: string) {
    this.token = token;
    localStorage.setItem('token', token);
  }

  public clearToken() {
    this.token = null;
    localStorage.removeItem('token');
  }

  public async getUserInfo(): Promise<UserInfo> {
    try {
      const response = await axios.get<UserInfo>(`${API_BASE_URL}/api/users/me`, {
        headers: this.getHeaders(),
      });
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 401) {
          this.clearToken();
          throw new Error('인증이 만료되었습니다. 다시 로그인해주세요.');
        }
        throw new Error(error.response?.data?.message || '사용자 정보를 불러오는데 실패했습니다.');
      }
      throw new Error('알 수 없는 오류가 발생했습니다.');
    }
  }

  public async logout(): Promise<void> {
    try {
      await axios.post(`${API_BASE_URL}/api/auth/logout`, {}, {
        headers: this.getHeaders(),
      });
      this.clearToken();
    } catch (error) {
      // 로그아웃 실패 시에도 토큰은 제거
      this.clearToken();
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.message || '로그아웃 중 오류가 발생했습니다.');
      }
      throw new Error('알 수 없는 오류가 발생했습니다.');
    }
  }
}

export const userService = UserService.getInstance(); 