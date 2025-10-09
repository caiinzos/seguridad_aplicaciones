package es.storeapp.web.config;

import es.storeapp.business.utils.InputSanitizer;
import es.storeapp.web.forms.UserProfileForm;
import es.storeapp.web.forms.CommentForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class XSSanitizerResolver implements HandlerMethodArgumentResolver {

    @Autowired
    private InputSanitizer inputSanitizer;

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        // Aplicar a todos los forms que puedan contener XSS
        return parameter.getParameterType().equals(UserProfileForm.class) ||
                parameter.getParameterType().equals(CommentForm.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) throws Exception {

        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
        Object formObject = binderFactory.createBinder(webRequest, null, parameter.getParameterName()).getTarget();

        if (formObject instanceof UserProfileForm) {
            UserProfileForm form = (UserProfileForm) formObject;
            if(form.getName() != null) form.setName(inputSanitizer.sanitize(form.getName()));
            if(form.getAddress() != null) form.setAddress(inputSanitizer.sanitize(form.getAddress()));
            return form;
        }
        else if (formObject instanceof CommentForm) {
            CommentForm form = (CommentForm) formObject;
            if(form.getText() != null) form.setText(inputSanitizer.sanitize(form.getText()));
            return form;
        }

        return formObject;
    }
}