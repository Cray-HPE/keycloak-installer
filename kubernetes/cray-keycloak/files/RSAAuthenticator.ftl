<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",realm.name)}
    <#elseif section = "header">
        ${msg("loginTitleHtml",realm.name)}
    <#elseif section = "form">
        <form id="loginform" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <input id="sharedUsername" name="sharedUsername" value="${sharedUsername}" type="hidden">
            <#if sharedUsername = "false">
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcInputWrapperClass!}">
                        <div>
                            ${usernameMessage}
                        </div>
                        <input id="rsa_username" name="rsa_username" type="visible" class="${properties.kcInputClass!}" autofocus/>
                    </div>
                </div>
            </#if>
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcInputWrapperClass!}">
                    <div>
                        ${otpMessage}
                    </div>
                    <input id="rsa_otp" name="rsa_otp" type="visible" class="${properties.kcInputClass!}" autofocus/>
                </div>
            </div>
            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}"/>
                </div>
                <input id="otpMessage" name="otpMessage" value="${otpMessage}" type="hidden">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                               name="cancel" id="kc-cancel" type="submit" value="${msg("doCancel")}"/>
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
