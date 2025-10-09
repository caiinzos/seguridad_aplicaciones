package es.storeapp.web.filters;

import es.storeapp.business.utils.InputSanitizer;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.util.*;

@Component
public class XSSFilter implements Filter {

    @Autowired
    private InputSanitizer inputSanitizer;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws java.io.IOException, ServletException {
        chain.doFilter(new XSSRequestWrapper((HttpServletRequest) request, inputSanitizer), response);
    }
}

class XSSRequestWrapper extends HttpServletRequestWrapper {
    private final InputSanitizer sanitizer;

    public XSSRequestWrapper(HttpServletRequest request, InputSanitizer sanitizer) {
        super(request);
        this.sanitizer = sanitizer;
    }

    @Override
    public String[] getParameterValues(String parameter) {
        String[] values = super.getParameterValues(parameter);
        if (values == null) return null;

        String[] encodedValues = new String[values.length];
        for (int i = 0; i < values.length; i++) {
            encodedValues[i] = sanitizer.sanitize(values[i]);
        }
        return encodedValues;
    }

    @Override
    public String getParameter(String parameter) {
        String value = super.getParameter(parameter);
        return sanitizer.sanitize(value);
    }
}