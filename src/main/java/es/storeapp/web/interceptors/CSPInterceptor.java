package es.storeapp.web.interceptors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

public class CSPInterceptor implements HandlerInterceptor {
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
        throws Exception {
        response.setHeader("Content-Security-Policy",
                "default-src 'self'; " +
                        "base-uri 'self'; " +
                        "object-src 'none'; " +
                        "frame-ancestors 'self'; " +
                        "form-action 'self'; " +
                        "img-src 'self' data:; " +           
                        "font-src 'self' data:; " +            
                        "connect-src 'self'; " +               
                        "script-src 'self' 'unsafe-inline'; " +
                        "style-src 'self' 'unsafe-inline'; " + 
                        "upgrade-insecure-requests;");         
        return true;
    }
    
