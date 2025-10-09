package es.storeapp.web.config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import java.util.List;

import es.storeapp.business.services.UserService;
import es.storeapp.common.ConfigurationParameters;
import es.storeapp.common.Constants;
import es.storeapp.web.interceptors.AuthenticatedUserInterceptor;
import es.storeapp.web.interceptors.AutoLoginInterceptor;
import es.storeapp.web.interceptors.CSPInterceptor;
import es.storeapp.web.interceptors.LoggerInterceptor;
import es.storeapp.web.interceptors.ShoppingCartInterceptor;
import java.io.File;

import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Autowired
    ConfigurationParameters configurationParameters;
    
    @Autowired
    private UserService userService;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        
        /* AutoLogin detecting the persistent cookie */
        registry.addInterceptor(new AutoLoginInterceptor(userService))
                .addPathPatterns(Constants.ALL_ENDPOINTS)
                .excludePathPatterns(Constants.LIBS_RESOURCES)
                .excludePathPatterns(Constants.EXTERNAL_RESOURCES);
        
        /* CSP interceptor */
        registry.addInterceptor(new CSPInterceptor())
                .addPathPatterns(Constants.ALL_ENDPOINTS)
                .excludePathPatterns(Constants.LIBS_RESOURCES)
                .excludePathPatterns(Constants.EXTERNAL_RESOURCES);
        
        /* Request log interceptor */
        registry.addInterceptor(new LoggerInterceptor());
        
        /* Shopping cart guard */
        registry.addInterceptor(new ShoppingCartInterceptor())
                .addPathPatterns(Constants.ALL_ENDPOINTS)
                .excludePathPatterns(Constants.LIBS_RESOURCES)
                .excludePathPatterns(Constants.EXTERNAL_RESOURCES);
        
        /* Interceptor to protect authenticated resources */
        registry.addInterceptor(new AuthenticatedUserInterceptor())
            .addPathPatterns(Constants.ORDERS_ALL_ENDPOINTS)
            .addPathPatterns(Constants.USER_PROFILE_ALL_ENDPOINTS)
            .addPathPatterns(Constants.CHANGE_PASSWORD_ENDPOINT)
            .addPathPatterns(Constants.COMMENT_PRODUCT_ENDPOINT);
    }
    
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler(Constants.EXTERNAL_RESOURCES)
                .addResourceLocations(new File(configurationParameters.getResources()).toURI().toString());
    }

    @Autowired
    private XSSanitizerResolver xssSanitizerResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(xssSanitizerResolver);
    }
}
