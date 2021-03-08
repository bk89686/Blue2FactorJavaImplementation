# Blue2FactorJavaImplementation

## Blue2Factor is passwordless first and second factor authentication

To learn about this product, please see https://www.blue2factor.com.

To use Blue2Factor, place this code at the top of each page you would like protected:


```
   Blue2Factor b2f = new Blue2Factor();
   String redirect = b2fRedirect(jwt, currentUrl);
   if (redirect != null) {
       //redirect to the page: redirect
   } else {
       // show your page
   }
```
Also, add these two dependencies:
```
     <dependency>
         <groupId>org.json</groupId>
         <artifactId>json</artifactId>
         <version>20200518</version>
     </dependency>
     <dependency>
         <groupId>io.jsonwebtoken</groupId>
         <artifactId>jjwt-api</artifactId>
         <version>0.11.2</version>
     </dependency>
```
Please contact us at help@blue2factor.com or use the contact info at https://www.blue2factor.com/contactUs.

We are here to help!
