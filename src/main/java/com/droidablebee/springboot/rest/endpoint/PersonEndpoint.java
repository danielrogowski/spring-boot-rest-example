package com.droidablebee.springboot.rest.endpoint;

import javax.validation.Valid;
import javax.validation.constraints.Size;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.droidablebee.springboot.rest.config.WebSecurityConfig;
import com.droidablebee.springboot.rest.domain.Person;
import com.droidablebee.springboot.rest.service.PersonService;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

@RestController
@RequestMapping(produces = { MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
@Validated // required for @Valid on method parameters such as @RequesParam, @PathVariable,
           // @RequestHeader
public class PersonEndpoint extends BaseEndpoint {

    static final int      DEFAULT_PAGE_SIZE       = 10;
    static final String   HEADER_TOKEN            = "token";
    static final String   HEADER_USER_ID          = "userId";

    static final String   PERSON_READ_PERMISSION  = WebSecurityConfig.ROLE_NAME_USER_READ;
    static final String   PERSON_WRITE_PERMISSION = WebSecurityConfig.ROLE_NAME_USER_WRITE;

    @Autowired
    private PersonService personService;

//    @PreAuthorize("hasAuthority('" + PERSON_READ_PERMISSION + "')")
//    @PreAuthorize("hasRole('USER_READ')")
    @PreAuthorize("hasAuthority('SCOPE_" + PERSON_READ_PERMISSION + "')")
    @RequestMapping(path = "/v1/persons", method = RequestMethod.GET)
    @ApiOperation(value = "Get all persons", notes = "Returns first N persons specified by the size parameter with page offset specified by page parameter.", response = Page.class)
    public Page<Person> getAll(
            @ApiParam("The size of the page to be returned") @RequestParam(required = false) Integer size,
            @ApiParam("Zero-based page index") @RequestParam(required = false) Integer page) {

        if (size == null) {
            size = DEFAULT_PAGE_SIZE;
        }
        if (page == null) {
            page = 0;
        }

        Pageable pageable = PageRequest.of(page, size);
        Page<Person> persons = personService.findAll(pageable);

        return persons;
    }

    @PreAuthorize("hasAuthority('SCOPE_" + PERSON_READ_PERMISSION + "')")
    @RequestMapping(path = "/v1/person/{id}", method = RequestMethod.GET)
    @ApiOperation(value = "Get person by id", notes = "Returns person for id specified.", response = Person.class)
    @ApiResponses(value = { @ApiResponse(code = 404, message = "Person not found") })
    public ResponseEntity<Person> get(@ApiParam("Person id") @PathVariable("id") Long id) {

        Person person = personService.findOne(id);
        return (person == null ? ResponseEntity.status(HttpStatus.NOT_FOUND) : ResponseEntity.ok()).body(person);
    }

    @PreAuthorize("hasAuthority('SCOPE_" + PERSON_WRITE_PERMISSION + "')")
    @RequestMapping(path = "/v1/person", method = RequestMethod.PUT, consumes = { MediaType.APPLICATION_JSON_VALUE,
            MediaType.APPLICATION_XML_VALUE })
    @ApiOperation(value = "Create new or update existing person", notes = "Creates new or updates existing person. Returns created/updated person with id.", response = Person.class)
    public ResponseEntity<Person> add(@Valid @RequestBody Person person,
            @Valid @Size(max = 40, min = 8, message = "user id size 8-40") @RequestHeader(name = HEADER_USER_ID) String userId,
            @Valid @Size(max = 40, min = 2, message = "token size 2-40") @RequestHeader(name = HEADER_TOKEN, required = false) String token) {

        person = personService.save(person);
        return ResponseEntity.ok()
                .body(person);
    }

    @InitBinder("person")
    protected void initBinder(WebDataBinder binder) {
        binder.addValidators(new PersonValidator());
    }
}
