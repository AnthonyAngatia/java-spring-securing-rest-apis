package io.jzheaux.springsecurity.resolutions;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RestController
public class ResolutionController {
    private final ResolutionRepository resolutions;

    public ResolutionController(ResolutionRepository resolutions) {
        this.resolutions = resolutions;
    }

    @GetMapping("/resolutions")
    @PreAuthorize("hasAuthority('resolution:read')")
    public Iterable<Resolution> read() {
        return this.resolutions.findAll();
    }

    @GetMapping("/resolution/{id}")
    @PreAuthorize("hasAuthority('resolution:read')")
    public Optional<Resolution> read(@PathVariable("id") UUID id) {
        return this.resolutions.findById(id);
    }

    @PostMapping("/resolution")
    @PreAuthorize("hasAuthority('resolution:write')")
    public Resolution make(@CurrentUsername String owner, @RequestBody String text) {
        Resolution resolution = new Resolution(text, owner);
        return this.resolutions.save(resolution);
    }

    /**
     * Alternative ways of doing make
     */
//    @PostMapping("/resolution")
//    public Resolution make(@CurrentSecurityContext SecurityContext ctx, @RequestBody String text) {
//        User user = (User) ctx.getAuthentication().getPrincipal();
//        // ...
//    }

//    @PostMapping("/resolution")
//    public Resolution make(@CurrentSecurityContext(expression="authentication.name") String owner, @RequestBody String text) {
//        Resolution resolution = new Resolution(text, owner);
//        return this.resolutions.save(resolution);
//    }

    @PutMapping(path = "/resolution/{id}/revise")
    @PreAuthorize("hasAuthority('resolution:write')")
    @Transactional
    public Optional<Resolution> revise(@PathVariable("id") UUID id, @RequestBody String text) {
        this.resolutions.revise(id, text);
        return read(id);
    }

    @PutMapping("/resolution/{id}/complete")
    @Transactional
    @PreAuthorize("hasAuthority('resolution:write')")
    public Optional<Resolution> complete(@PathVariable("id") UUID id) {
        this.resolutions.complete(id);
        return read(id);
    }
}
