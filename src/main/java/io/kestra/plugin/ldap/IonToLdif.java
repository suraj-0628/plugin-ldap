package io.kestra.plugin.ldap;

import com.amazon.ion.IonException;
import com.amazon.ion.IonReader;
import com.amazon.ion.UnknownSymbolException;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.ldif.LDIFRecord;
import com.unboundid.ldif.LDIFWriter;

import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.models.annotations.Metric;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.executions.metrics.Counter;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;

import io.micronaut.core.annotation.Nullable;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotNull;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import java.net.URI;

import java.util.ArrayList;
import java.util.List;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import org.slf4j.Logger;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Combine ION entries into an LDIF file for an LDAP server.",
    description = "Transform .ion files to .ldif ones."
)
@Plugin(
    examples = {
        @io.kestra.core.models.annotations.Example(
            title = "YAML: Make LDIF entries from ION ones.",
            full = true,
            code = """
                id: ldap_ion_to_ldif
                namespace: company.team

                inputs:
                  - id: file1
                    type: FILE
                  - id: file2
                    type: FILE

                tasks:
                  - id: ion_to_ldiff
                    type: io.kestra.plugin.ldap.IonToLdif
                    inputs:
                      - "{{ inputs.file1 }}"
                      - "{{ inputs.file2 }}"
                """
        ),
        @io.kestra.core.models.annotations.Example(
            title = "INPUT example: here's an ION file content that may be inputted :",
            code = {"""
            # simple entry
            {dn:"cn=bob@orga.com,ou=diffusion_list,dc=orga,dc=com",attributes:{description:["Some description","Some other description"],someOtherAttribute:["perhaps","perhapsAgain"]}}
            # modify changeRecord
            {dn:"cn=triss@orga.com,ou=diffusion_list,dc=orga,dc=com",changeType:"modify",modifications:[{operation:"DELETE",attribute:"description",values:["Some description 3"]},{operation:"ADD",attribute:"description",values:["Some description 4"]},{operation:"REPLACE",attribute:"someOtherAttribute",values:["Loves herself more"]}]}
            # delete changeRecord
            {dn:"cn=triss@orga.com,ou=diffusion_list,dc=orga,dc=com",changeType:"delete"}
            # moddn changeRecord (it is mandatory to specify a newrdn and a deleteoldrdn)
            {dn:"cn=triss@orga.com,ou=diffusion_list,dc=orga,dc=com",changeType:"moddn",newDn:{newrdn:"cn=triss@orga.com",deleteoldrdn:false,newsuperior:"ou=expeople,dc=example,dc=com"}}
            # moddn changeRecord without new superior (it is optional to specify a new superior field)
            {dn:"cn=triss@orga.com,ou=diffusion_list,dc=orga,dc=com",changeType:"moddn",newDn:{newrdn:"cn=triss@orga.com",deleteoldrdn:true}}
            """},
            full = true
        ),
        @io.kestra.core.models.annotations.Example(
            title = "OUTPUT example: here's an LDIF file content that may be outputted :",
            code = {"""
            # simple entry
            dn: cn=bob@orga.com,ou=diffusion_list,dc=orga,dc=com
            description: Some description
            someOtherAttribute: perhaps
            description: Some other description
            someOtherAttribute: perhapsAgain

            # modify changeRecord
            dn: cn=triss@orga.com,ou=diffusion_list,dc=orga,dc=com
            changetype: modify
            delete: description
            description: Some description 3
            -
            add: description
            description: Some description 4
            -
            replace: someOtherAttribute
            someOtherAttribute: Loves herself more
            -

            # delete changeRecord
            dn: cn=triss@orga.com,ou=diffusion_list,dc=orga,dc=com
            changetype: delete

            # moddn with new superior
            dn: cn=triss@orga.com,ou=diffusion_list,dc=orga,dc=com
            changetype: moddn
            newrdn: cn=triss@orga.com
            deleteoldrdn: 0
            newsuperior: ou=expeople,dc=example,dc=com

            # moddn without new superior
            dn: cn=triss@orga.com,ou=diffusion_list,dc=orga,dc=com
            changetype: moddn
            newrdn: cn=triss@orga.com
            deleteoldrdn: 1
            """},
            full = true
        )
    },
     metrics = {
        @Metric(
            name = "entries.found",
            type = Counter.TYPE,
            unit = "entries",
            description = "Number of entries found during Ion to LDIF conversion"
        ),
        @Metric(
            name = "entries.translated",
            type = Counter.TYPE,
            unit = "entries",
            description = "Number of entries successfully translated to LDIF format"
        )
    }
)
public class IonToLdif extends Task implements RunnableTask<IonToLdif.Output> {
    /**
     * INPUTS ------------------------------------------------------------------------------------------------------------------- //
    **/

    @Schema(
        title = "URI(s) of file(s) containing ION entries."
    )
    @PluginProperty(dynamic = true)
    @NotNull
    private List<String> inputs;

    /**
     * OUTPUTS ------------------------------------------------------------------------------------------------------------------- //
    **/

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(
            title = "LDIF transformed file(s) URI(s)."
        )
        private final List<URI> urisList;
    }

    /**
     * CODE ------------------------------------------------------------------------------------------------------------------- //
    **/

    /** Private util class to store DN modification informations. */
    @Builder
    @Getter
    static class NewDn {
        @NotNull
        String newRDN;
        @NotNull
        Boolean deleteOldRDN;
        @Nullable
        String newsuperior;
    }

    @Getter(AccessLevel.NONE)
    @Setter(AccessLevel.NONE)
    @Default
    private Integer count = 0;
    @Getter(AccessLevel.NONE)
    @Setter(AccessLevel.NONE)
    @Default
    private Integer found = 0;
    /** The kestra logger (slf4j) for the task. */
    @Getter(AccessLevel.NONE)
    @Setter(AccessLevel.NONE)
    @Default
    private Logger logger = null;

    @Override
    public IonToLdif.Output run(RunContext runContext) throws Exception {
        this.logger = runContext.logger();
        List<URI> storedResults = new ArrayList<>();

        for (String path : this.inputs) {
            try {
                storedResults.add(transformIonToLdif(path, runContext));
            } catch (Exception e) {
                this.logger.error(e.getMessage());
            }
        }
        if (!this.inputs.isEmpty() && storedResults.isEmpty()) {
            throw new Exception("Not a single file has been translated.");
        }
        runContext.metric(Counter.of("entries.found", this.found, "origin", "Ionise"));
        runContext.metric(Counter.of("entries.translated", this.count, "origin", "Ionise"));
        return Output.builder()
            .urisList(storedResults)
            .build();
    }

    /**
     * Transforms a given ION file to LDIF format.
     * @param ionFilePath : The path to the ION file to be transformed.
     * @param runContext : The context of the run.
     * @return URI of the transformed LDIF file.
     */
    private URI transformIonToLdif(String ionFilePath, RunContext runContext) throws IllegalStateException, IonException, IllegalArgumentException, IOException, IllegalVariableEvaluationException, NullPointerException, IllegalArgumentException {
        try (IonReader ionReader = Utils.getIONReaderFromUri(ionFilePath, runContext);
             ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             LDIFWriter ldifWriter = new LDIFWriter(byteArrayOutputStream)) {

            processIonEntries(ionReader, ldifWriter);
            ldifWriter.flush();

            File tempFile = runContext.workingDir().createTempFile(byteArrayOutputStream.toByteArray(), ".ldif").toFile();
            return runContext.storage().putFile(tempFile);
        }
    }

    /**
     * Processes the entries from the ION reader and attempts to write them to the LDIF writer.
     * @param ionReader : The ION reader containing the entries to be processed.
     * @param ldifWriter : The LDIF writer to write the entries to.
     */
    private void processIonEntries(IonReader ionReader, LDIFWriter ldifWriter) throws IOException, IllegalStateException  {
        while (ionReader.next() != null) {
            ionReader.stepIn();
            LDIFRecord entry = null;
            this.found++;
            try {
                entry = readIonEntry(ionReader);
            } catch (Exception e) {
                this.logger.error("Unable to read entry {}", e.getMessage());
            }
            if (entry != null) {
                try {
                    ldifWriter.writeLDIFRecord(entry);
                    this.count++;
                } catch (Exception e) {
                    this.logger.error("Unable to write entry {} : {}", entry.toString(), e.getMessage());
                }
            }
            ionReader.stepOut();
        }
    }

    /**
     * Reads an entry from the ION reader.
     * @param ionReader : The ION reader to read the entry from.
     * @return The LDIF entry read from the ION reader.
     */
    private LDIFRecord readIonEntry(IonReader ionReader) throws UnknownSymbolException, IllegalStateException {
        String dn = null;
        List<Attribute> attributes = null;
        String changeType = null;
        List<Modification> modifications = null;
        NewDn newDn = null;

        while (ionReader.next() != null) {
            String fieldName = ionReader.getFieldName();
            if ("dn".equals(fieldName)) {
                dn = ionReader.stringValue();
            } else if ("attributes".equals(fieldName)) {
                ionReader.stepIn();
                attributes = readAttributes(ionReader);
                ionReader.stepOut();
            } else if ("changeType".equals(fieldName)) {
                changeType = ionReader.stringValue();
            } else if ("modifications".equals(fieldName) && "modify".equals(changeType)) {
                ionReader.stepIn();
                modifications = readModifications(ionReader);
                ionReader.stepOut();
            } else if ("newDn".equals(fieldName) && "moddn".equals(changeType)) {
                ionReader.stepIn();
                newDn = readNewDn(ionReader);
                ionReader.stepOut();
            } else {
                this.logger.warn("Unrecognized field : {}", fieldName);
            }
        }

        if (dn != null) {
            if (changeType == null) {
                return new Entry(dn, attributes);
            } else if ("add".equals(changeType)) {
                return new LDIFAddChangeRecord(dn, attributes);
            } else if ("delete".equals(changeType)) {
                return new LDIFDeleteChangeRecord(dn);
            } else if ("modify".equals(changeType) && modifications != null) {
                return new LDIFModifyChangeRecord(dn, modifications.toArray(new Modification[0]));
            } else if ("moddn".equals(changeType) && newDn != null) {
                return new LDIFModifyDNChangeRecord(dn, newDn.newRDN, newDn.deleteOldRDN, newDn.newsuperior);
            }
            this.logger.warn("Unable to make Ion entry from DN : {}, Attributes {}", dn, attributes);
        } else {
            this.logger.warn("Entry nb {} does not contain a DN", this.found);
        }
        return null;
    }

    /**
     * Read the informations of the new DN.
     * @param ionReader : The ION reader to read the specific moddn attributes from.
     * @return A NewDn util class containing the new DN read informations.
     */
    private NewDn readNewDn(IonReader ionReader) throws UnknownSymbolException {
        String newRDN = null;
        Boolean deleteOldRDN = null;
        String newsuperior = null;
        while (ionReader.next() != null) {
            if (ionReader.getFieldName().equals("newrdn")) newRDN = ionReader.stringValue();
            else if (ionReader.getFieldName().equals("deleteoldrdn")) deleteOldRDN = ionReader.booleanValue();
            else if (ionReader.getFieldName().equals("newsuperior")) newsuperior = ionReader.stringValue();
        }
        return new NewDn(newRDN, deleteOldRDN, newsuperior);
    }

    /**
     * Read each modifications informations.
     * @param ionReader : The ION reader to read the specific modify operations from.
     * @return A list of Modification to apply to the entry.
     */
    private List<Modification> readModifications(IonReader ionReader) throws IllegalStateException, UnknownSymbolException {
        List<Modification> modifications = new ArrayList<>();
        while (ionReader.next() != null) {
            ionReader.stepIn();
            String operation = null;
            String attributeName = null;
            List<String> values = new ArrayList<>();

            while (ionReader.next() != null) {
                String fieldName = ionReader.getFieldName();
                if ("operation".equals(fieldName)) {
                    operation = ionReader.stringValue();
                } else if ("attribute".equals(fieldName)) {
                    attributeName = ionReader.stringValue();
                } else if ("values".equals(fieldName)) {
                    ionReader.stepIn();
                    while (ionReader.next() != null) {
                        values.add(ionReader.stringValue());
                    }
                    ionReader.stepOut();
                } else {
                    this.logger.warn("Unrecognized field in modification: {}", fieldName);
                }
            }

            if (operation != null && attributeName != null) {
                ModificationType modType = null;
                switch (operation) {
                    case "ADD":
                        modType = ModificationType.ADD;
                        break;
                    case "DELETE":
                        modType = ModificationType.DELETE;
                        break;
                    case "INCREMENT":
                        modType = ModificationType.INCREMENT;
                        break;
                    case "REPLACE":
                        modType = ModificationType.REPLACE;
                        break;
                }
                modifications.add(new Modification(modType, attributeName, values.toArray(new String[0])));
            }
            ionReader.stepOut();
        }
        return modifications;
    }

    /**
     * Reads the attributes of an entry from the ION reader.
     * @param ionReader : The ION reader to read the attributes from.
     * @return A list of attributes read from the ION reader.
     */
    private List<Attribute> readAttributes(IonReader ionReader) throws IllegalStateException, UnknownSymbolException {
        List<Attribute> attributes = new ArrayList<>();

        while (ionReader.next() != null) {
            String attributeName = ionReader.getFieldName();
            ionReader.stepIn();
            List<String> values = new ArrayList<>();
            while (ionReader.next() != null) {
                values.add(ionReader.stringValue());
            }
            ionReader.stepOut();
            attributes.add(new Attribute(attributeName, values));
        }

        return attributes;
    }
}
